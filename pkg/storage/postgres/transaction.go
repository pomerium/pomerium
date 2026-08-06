package postgres

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

const (
	transactionMaxDuration = time.Minute
	transactionMaxRetries  = 3
	transactionFinishGrace = 10 * time.Second
)

func (backend *Backend) doTransaction(
	ctx context.Context, key string, fn func(tx storage.Transaction) error,
) ([]*databroker.Record, error) {
	serverVersion, pool, err := backend.init(ctx)
	if err != nil {
		return nil, err
	}

	release, err := backend.acquireTransactionSlot()
	if err != nil {
		return nil, err
	}
	defer release()

	// TODO : better retry
	for attempt := 0; ; attempt++ {
		changed, err := backend.runTransaction(ctx, pool, serverVersion, key, fn)
		if err != nil && isSerializationFailure(err) && attempt < transactionMaxRetries {
			continue
		}
		return changed, err
	}
}

func (backend *Backend) runTransaction(
	ctx context.Context,
	pool *pgxpool.Pool,
	serverVersion uint64,
	key string,
	fn func(tx storage.Transaction) error,
) ([]*databroker.Record, error) {
	pgtx, err := pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	// covers failures (Rollback after Commit is a no-op)
	defer func() { _ = pgtx.Rollback(ctx) }()

	if err := acquireTransactionLock(ctx, pgtx, key); err != nil {
		return nil, err
	}

	tx := &transaction{backend: backend, ctx: ctx, tx: pgtx, serverVersion: serverVersion}
	if err := fn(tx); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	// a rolled back transaction must not notify, so this runs on the pool after
	// the commit rather than inside it
	finishCtx, cancel := commitContext(ctx)
	defer cancel()
	if err := signalRecordChange(finishCtx, pool); err != nil {
		return nil, err
	}
	return tx.changed, nil
}

// acquireTransactionSlot clamps the maximum number of in-flight, potentially long-lived transaction
// operations so a callback holding a connection can never block other databroker operations
func (backend *Backend) acquireTransactionSlot() (release func(), err error) {
	// TODO: semaphore?
	select {
	case backend.txSlots <- struct{}{}:
		return func() { <-backend.txSlots }, nil
	default:
		return nil, status.Error(codes.ResourceExhausted, "too many concurrent transactions")
	}
}

// commitContext detaches from ctx so a transaction whose callback has returned
// still commits when the backend is closing.
func commitContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), transactionFinishGrace)
}

type transaction struct {
	backend       *Backend
	ctx           context.Context
	serverVersion uint64

	mu        sync.Mutex
	tx        pgx.Tx
	err       error
	responses []*databroker.TransactionResponse
	changed   []*databroker.Record
}

// Submit applies a single operation to the open postgres transaction. Once an
// operation fails inside postgres the transaction is aborted and every later
// Submit fails with that first error.
func (tx *transaction) Submit(req *databroker.TransactionRequest) (*databroker.TransactionResponse, error) {
	if tx.ctx.Err() != nil {
		return nil, context.Cause(tx.ctx)
	}

	// pgx.Tx is not safe for concurrent use
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.err != nil {
		return nil, tx.err
	}

	var res *databroker.TransactionResponse
	var err error
	switch op := req.GetOperation().(type) {
	case *databroker.TransactionRequest_Get:
		res, err = tx.submitGetLocked(op.Get)
	case *databroker.TransactionRequest_Put:
		res, err = tx.submitPutLocked(op.Put)
	case *databroker.TransactionRequest_Patch:
		res, err = tx.submitPatchLocked(op.Patch)
	case *databroker.TransactionRequest_Query:
		res, err = tx.submitQueryLocked(op.Query)
	default:
		err = status.Errorf(codes.InvalidArgument, "unsupported transaction operation: %T", req.GetOperation())
	}
	if err != nil {
		if isPostgresError(err) {
			tx.err = err
		}
		return nil, err
	}

	res.Key = req.GetKey()
	tx.responses = append(tx.responses, res)
	return res, nil
}

func (tx *transaction) Commit() error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	ctx, cancel := commitContext(tx.ctx)
	defer cancel()

	return tx.tx.Commit(ctx)
}

func (tx *transaction) submitGetLocked(req *databroker.GetRequest) (*databroker.TransactionResponse, error) {
	record, err := getRecord(tx.ctx, tx.tx, req.GetType(), req.GetId(), lockModeNone)
	if err != nil {
		return nil, err
	}
	return &databroker.TransactionResponse{
		Operation: &databroker.TransactionResponse_Get{Get: &databroker.GetResponse{Record: record}},
	}, nil
}

func (tx *transaction) submitPutLocked(req *databroker.PutRequest) (*databroker.TransactionResponse, error) {
	now := timestamppb.Now()
	records := make([]*databroker.Record, 0, len(req.GetRecords()))
	recordTypes := map[string]struct{}{}
	for _, record := range req.GetRecords() {
		record = proto.CloneOf(record)
		record.ModifiedAt = now
		if err := putRecordAndChange(tx.ctx, tx.tx, record); err != nil {
			return nil, err
		}
		recordTypes[record.GetType()] = struct{}{}
		records = append(records, record)
	}

	for recordType := range recordTypes {
		if err := tx.enforceOptionsLocked(recordType); err != nil {
			return nil, err
		}
	}

	tx.changed = append(tx.changed, records...)
	return &databroker.TransactionResponse{
		Operation: &databroker.TransactionResponse_Put{Put: &databroker.PutResponse{
			ServerVersion: tx.serverVersion,
			Records:       records,
		}},
	}, nil
}

func (tx *transaction) enforceOptionsLocked(recordType string) error {
	options, err := getOptions(tx.ctx, tx.tx, recordType)
	if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
		options = new(databroker.Options)
	} else if err != nil {
		return err
	}
	return enforceOptions(tx.ctx, tx.tx, recordType, options)
}

func (tx *transaction) submitPatchLocked(req *databroker.PatchRequest) (*databroker.TransactionResponse, error) {
	now := timestamppb.Now()
	patched := make([]*databroker.Record, 0, len(req.GetRecords()))
	for _, record := range req.GetRecords() {
		record = proto.CloneOf(record)
		record.ModifiedAt = now
		err := patchRecordIn(tx.ctx, tx.tx, record, req.GetFieldMask())
		if storage.IsNotFound(err) {
			continue
		} else if err != nil {
			return nil, err
		}
		patched = append(patched, record)
	}

	tx.changed = append(tx.changed, patched...)
	return &databroker.TransactionResponse{
		Operation: &databroker.TransactionResponse_Patch{Patch: &databroker.PatchResponse{
			ServerVersion: tx.serverVersion,
			Records:       patched,
		}},
	}, nil
}

func (tx *transaction) submitQueryLocked(req *databroker.QueryRequest) (*databroker.TransactionResponse, error) {
	expr, err := storage.FilterExpressionFromStruct(req.GetFilter())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid query filter: %v", err)
	}
	if recordType := req.GetType(); recordType != "" {
		f := storage.MustEqualsFilterExpression("type", recordType)
		if expr != nil {
			expr = storage.AndFilterExpression{expr, f}
		} else {
			expr = f
		}
	}

	all, err := tx.listLatestRecordsLocked(expr)
	if err != nil {
		return nil, err
	}

	query := strings.ToLower(req.GetQuery())
	filtered := make([]*databroker.Record, 0, len(all))
	for _, record := range all {
		if query != "" && !storage.MatchAny(record.GetData(), query) {
			continue
		}
		filtered = append(filtered, record)
	}

	_, recordVersion, err := getRecordVersionRange(tx.ctx, tx.tx)
	if err != nil {
		return nil, err
	}

	records, totalCount := databroker.ApplyOffsetAndLimit(filtered, int(req.GetOffset()), int(req.GetLimit()))
	return &databroker.TransactionResponse{
		Operation: &databroker.TransactionResponse_Query{Query: &databroker.QueryResponse{
			Records:       records,
			TotalCount:    int64(totalCount),
			ServerVersion: tx.serverVersion,
			RecordVersion: recordVersion,
		}},
	}, nil
}

// listLatestRecordsLocked pages over the open transaction so the query sees the
// transaction's own uncommitted writes.
func (tx *transaction) listLatestRecordsLocked(expr storage.FilterExpression) ([]*databroker.Record, error) {
	var all []*databroker.Record
	var lastRecordType, lastRecordID string
	for {
		records, err := listLatestRecordsAfter(tx.ctx, tx.tx, expr, lastRecordType, lastRecordID)
		if err != nil {
			return nil, err
		}
		all = append(all, records...)
		if len(records) < recordBatchSize {
			return all, nil
		}
		last := records[len(records)-1]
		lastRecordType, lastRecordID = last.GetType(), last.GetId()
	}
}
