package postgres

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

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
	transactionMaxDuration = time.Minute
	transactionMaxRetries  = 3
	transactionJoinBackoff = 10 * time.Millisecond
)

func (backend *Backend) doTransaction(
	ctx context.Context, key string, fn func(tx storage.Transaction) error,
) ([]*databroker.Record, bool, error) {
	serverVersion, pool, err := backend.init(ctx)
	if err != nil {
		return nil, false, err
	}
	// prevents open transactions from filling up the entire connection pool,
	// blocking other databroker operations.
	release, err := backend.acquireTransactionSlot()
	if err != nil {
		return nil, false, err
	}
	defer release()

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, false, err
	}
	lock := &flightLock{conn: conn, key: key}
	defer lock.release()

	// TODO : i don't think we should be retrying tryAcquire, otherwise we end up with transactions
	// that could be run twice (one after the other).
	for {
		leads, err := lock.tryAcquire(ctx)
		if err != nil {
			return nil, false, err
		}
		if leads {
			changed, err := backend.leadFlight(ctx, pool, lock, serverVersion, key, fn)
			return changed, false, err
		}

		changed, joined, err := backend.joinFlight(ctx, pool, key)
		if joined || err != nil {
			return changed, joined, err
		}

		// the leader holds the lock but has not published a flight yet, or died
		// without finishing one
		select {
		case <-ctx.Done():
			return nil, false, context.Cause(ctx)
		case <-time.After(transactionJoinBackoff):
		}
	}
}

// joinFlight waits for the transaction currently in flight on the key and
// returns its result. joined is false when there is nothing to share: no flight
// was in progress, or none completed before the deadline.
func (backend *Backend) joinFlight(
	ctx context.Context, pool *pgxpool.Pool, key string,
) ([]*databroker.Record, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, transactionMaxDuration)
	defer cancel()

	w, err := newFlightWaiter(ctx, pool)
	if err != nil {
		return nil, false, err
	}
	defer w.close()

	// LISTEN precedes this read, so any flight still running here will wake the
	// wait below
	before, err := getFlight(ctx, w.conn, key)
	if err != nil || before == nil || before.completed {
		return nil, false, err
	}

	woke, err := w.wait(ctx, before.id)
	if err != nil || !woke {
		return nil, false, err
	}

	after, err := getFlight(ctx, w.conn, key)
	if err != nil || after == nil || after.id != before.id || !after.completed {
		return nil, false, err
	}
	changed, err := after.result()
	return changed, true, err
}

// flightWaiter is a pooled connection listening for flight completions. Its
// LISTEN must never leak back into the pool, so on any failure the connection is
// closed instead.
type flightWaiter struct {
	conn   *pgxpool.Conn
	broken bool
}

func newFlightWaiter(ctx context.Context, pool *pgxpool.Pool) (*flightWaiter, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	w := &flightWaiter{conn: conn}
	if _, err := conn.Exec(ctx, `LISTEN `+transactionFlightNotifyName); err != nil {
		w.broken = true
		w.close()
		return nil, fmt.Errorf("postgres: failed to listen for transaction flights: %w", err)
	}
	return w, nil
}

func (w *flightWaiter) wait(ctx context.Context, flightID string) (bool, error) {
	for {
		n, err := w.conn.Conn().WaitForNotification(ctx)
		if err != nil {
			w.broken = true
			if errors.Is(err, context.DeadlineExceeded) {
				return false, nil
			}
			return false, fmt.Errorf("postgres: failed to wait for transaction flight: %w", err)
		}
		if n.Payload == flightID {
			return true, nil
		}
	}
}

func (w *flightWaiter) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if w.broken {
		_ = w.conn.Conn().Close(ctx)
	} else if _, err := w.conn.Exec(ctx, `UNLISTEN `+transactionFlightNotifyName); err != nil {
		_ = w.conn.Conn().Close(ctx)
	}
	w.conn.Release()
}

func (backend *Backend) leadFlight(
	ctx context.Context,
	pool *pgxpool.Pool,
	lock *flightLock,
	serverVersion uint64,
	key string,
	fn func(tx storage.Transaction) error,
) ([]*databroker.Record, error) {
	flightID := uuid.NewString()
	if err := lock.do(func(q querier) error {
		return beginFlight(ctx, q, key, flightID)
	}); err != nil {
		return nil, err
	}

	var changed []*databroker.Record
	var err error
	// TODO : better retry
	for attempt := 0; ; attempt++ {
		changed, err = backend.runTransaction(ctx, lock, serverVersion, fn)
		if err == nil || !isSerializationFailure(err) || attempt >= transactionMaxRetries {
			break
		}
	}

	finishErr := lock.do(func(q querier) error {
		return finishFlight(ctx, q, key, flightID, changed, err)
	})
	if err == nil && finishErr != nil {
		err = finishErr
	}
	if err != nil {
		return nil, err
	}
	if err := signalRecordChange(ctx, pool); err != nil {
		return nil, err
	}
	return changed, nil
}

func (backend *Backend) runTransaction(
	ctx context.Context,
	lock *flightLock,
	serverVersion uint64,
	fn func(tx storage.Transaction) error,
) ([]*databroker.Record, error) {
	var pgtx pgx.Tx
	if err := lock.begin(ctx, &pgtx); err != nil {
		return nil, err
	}

	tx := &transaction{backend: backend, ctx: ctx, tx: pgtx, lock: lock, serverVersion: serverVersion}
	if err := backend.registerTx(tx); err != nil {
		_ = pgtx.Rollback(ctx)
		return nil, err
	}
	defer backend.unregisterTx(tx)
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

// flightLock is a helper wrapper that owns a postgres connection and acquires advisory locks.
// It must own the postgres connection so that open transactions are cancellable by backend.Close.
type flightLock struct {
	key string

	mu       sync.Mutex
	conn     *pgxpool.Conn
	acquired bool
}

func (l *flightLock) do(fn func(q querier) error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return errBackendClosed
	}
	return fn(l.conn)
}

func (l *flightLock) begin(ctx context.Context, pgtx *pgx.Tx) error {
	return l.do(func(querier) error {
		var err error
		*pgtx, err = l.conn.Begin(ctx)
		return err
	})
}

func (l *flightLock) tryAcquire(ctx context.Context) (acquired bool, err error) {
	err = l.do(func(q querier) error {
		err := q.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, $2))`,
			l.key, int64(transactionLockSeed)).Scan(&acquired)
		l.acquired = l.acquired || acquired
		return err
	})
	if err != nil {
		return false, fmt.Errorf("postgres: failed to acquire transaction lock: %w", err)
	}
	return acquired, nil
}

// release must never hand a connection still holding the session lock back to
// the pool, so on any failure the connection is closed instead.
func (l *flightLock) release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if l.acquired && !l.unlock(ctx) {
		_ = l.conn.Conn().Close(ctx)
	}
	l.conn.Release()
	l.conn = nil
}

func (l *flightLock) unlock(ctx context.Context) (unlocked bool) {
	err := l.conn.QueryRow(ctx, `SELECT pg_advisory_unlock(hashtextextended($1, $2))`,
		l.key, int64(transactionLockSeed)).Scan(&unlocked)
	return err == nil && unlocked
}

// destroy closes the connection and hands it back to the pool so Close can
// drain while a transaction callback is still open by the caller.
func (l *flightLock) destroy() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return
	}
	_ = l.conn.Conn().Close(context.Background())
	l.conn.Release()
	l.conn = nil
}

func (backend *Backend) acquireTransactionSlot() (release func(), err error) {
	if !backend.texSem.TryAcquire(1) {
		return nil, status.Error(codes.ResourceExhausted, "too many concurrent transactions")
	}
	return func() {
		backend.texSem.Release(1)
	}, nil
}

func (backend *Backend) unregisterTx(tx *transaction) {
	backend.txMu.Lock()
	defer backend.txMu.Unlock()
	delete(backend.txs, tx)
}

func (backend *Backend) takeRegisteredTxs() []*transaction {
	backend.txMu.Lock()
	defer backend.txMu.Unlock()

	txs := slices.Collect(maps.Keys(backend.txs))
	backend.txs = nil
	return txs
}

func (backend *Backend) registerTx(tx *transaction) error {
	backend.txMu.Lock()
	defer backend.txMu.Unlock()

	if backend.closeCtx.Err() != nil {
		return context.Cause(backend.closeCtx)
	}
	if backend.txs == nil {
		backend.txs = make(map[*transaction]struct{})
	}
	backend.txs[tx] = struct{}{}
	return nil
}

type txResult struct {
	changed []*databroker.Record
	joined  bool
}

type transaction struct {
	backend       *Backend
	ctx           context.Context
	lock          *flightLock
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
	// unblocks a Submit
	_ = tx.tx.Conn().PgConn().CancelRequest(context.Background())

	tx.mu.Lock()
	defer tx.mu.Unlock()

	tx.err = err
	tx.lock.destroy()
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
