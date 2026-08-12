package postgres

import (
	"context"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/uuid"
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
	transactionJoinBackoff = 10 * time.Millisecond
	transactionJoinGrace   = time.Second
)

func (backend *Backend) newTransactionConn(ctx context.Context) (func(), uint64, *pgxpool.Conn, error) {
	serverVersion, pool, err := backend.init(ctx)
	if err != nil {
		return func() {}, serverVersion, nil, err
	}
	// prevents open transactions from filling up the entire connection pool,
	// blocking other databroker operations.
	release, err := backend.acquireTransactionSlot()
	if err != nil {
		return func() {}, serverVersion, nil, err
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return release, serverVersion, nil, err
	}
	return release, serverVersion, conn, nil
}

func (backend *Backend) doTransactionLocked(
	ctx context.Context,
	conn *pooledConn,
	serverVersion uint64,
	key string,
	fn func(tx storage.Transaction) error,
) ([]*databroker.Record, error) {
	flightID := uuid.NewString()
	if err := conn.do(func(q querier) error {
		return upsertNewEmptyTransaction(ctx, q, key, flightID)
	}); err != nil {
		return nil, err
	}
	b := backoff.WithContext(
		backoff.WithMaxRetries(backoff.NewExponentialBackOff(), 3),
		ctx,
	)
	changed, err := backoff.RetryWithData(func() ([]*databroker.Record, error) {
		changed, err := backend.runTransactionCallback(ctx, conn, serverVersion, fn)
		if isSerializationFailure(err) {
			return nil, err
		} else if err != nil {
			return nil, backoff.Permanent(err)
		}
		return changed, nil
	}, b)

	finishErr := conn.do(func(q querier) error {
		return updateTransactionResults(ctx, q, key, flightID, changed, err)
	})
	if err != nil {
		return nil, err
	}
	if finishErr != nil {
		return nil, finishErr
	}

	if err := conn.do(func(q querier) error {
		return signalRecordChange(ctx, q)
	}); err != nil {
		return nil, err
	}
	return changed, nil
}

func (backend *Backend) runTransactionCallback(
	ctx context.Context,
	conn *pooledConn,
	serverVersion uint64,
	fn func(tx storage.Transaction) error,
) ([]*databroker.Record, error) {
	pgtx, err := conn.begin(ctx)
	if err != nil {
		return nil, err
	}

	tx := &transaction{backend: backend, ctx: ctx, tx: pgtx, conn: conn, serverVersion: serverVersion}

	if err := backend.register(tx); err != nil {
		_ = pgtx.Rollback(ctx)
		return nil, err
	}
	defer backend.unregister(tx)
	// covers failures (Rollback after Commit is a no-op)
	defer tx.rollback()

	if err := fn(tx); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return tx.changed, nil
}

func (backend *Backend) acquireTransactionSlot() (release func(), err error) {
	if !backend.texSem.TryAcquire(1) {
		return nil, status.Error(codes.ResourceExhausted, "too many concurrent transactions")
	}
	return func() {
		backend.texSem.Release(1)
	}, nil
}

func (backend *Backend) unregister(k killable) {
	backend.txMu.Lock()
	defer backend.txMu.Unlock()
	delete(backend.txs, k)
}

func (backend *Backend) takeRegisteredTxs() []killable {
	backend.txMu.Lock()
	defer backend.txMu.Unlock()

	txs := slices.Collect(maps.Keys(backend.txs))
	backend.txs = nil
	return txs
}

func (backend *Backend) register(k killable) error {
	backend.txMu.Lock()
	defer backend.txMu.Unlock()

	if backend.closeCtx.Err() != nil {
		return context.Cause(backend.closeCtx)
	}
	if backend.txs == nil {
		backend.txs = make(map[killable]struct{})
	}
	backend.txs[k] = struct{}{}
	return nil
}

// killable is anything holding a pooled connection that Close must reclaim
// before the pool can drain.
type killable interface {
	kill(err error)
}

type txResult struct {
	changed []*databroker.Record
	joined  bool
}

type transaction struct {
	backend       *Backend
	ctx           context.Context
	conn          *pooledConn
	serverVersion uint64

	mu        sync.Mutex
	tx        pgx.Tx
	err       error
	responses []*databroker.TransactionResponse
	changed   []*databroker.Record
}

func (tx *transaction) rollback() {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if tx.err != nil {
		return
	}
	_ = tx.tx.Rollback(tx.ctx)
}

// kill fails the transaction and hands its connection back to the pool, from a
// goroutine other than the one running the callback.
func (tx *transaction) kill(err error) {
	// unblocks a Submit, which holds tx.mu while its query runs
	tx.conn.destroy()

	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.err = err
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
	if tx.err != nil {
		return tx.err
	}

	return tx.tx.Commit(tx.ctx)
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
