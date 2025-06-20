package postgres

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	"golang.org/x/sync/semaphore"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/pkg/contextutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/storage"
)

// Backend is a storage Backend implemented with Postgres.
type Backend struct {
	cfg             *config
	dsn             string
	onRecordChange  *signal.Signal
	onServiceChange *signal.Signal

	sem       *semaphore.Weighted
	component *telemetry.Component

	closeCtx context.Context
	close    context.CancelFunc

	mu            sync.RWMutex
	pool          *pgxpool.Pool
	serverVersion uint64
}

func (backend *Backend) acquire(ctx context.Context) error {
	if backend.sem == nil {
		return nil
	}
	ctx, op := backend.component.Start(ctx, "acquire")
	err := backend.sem.Acquire(ctx, 1)
	if err != nil {
		return op.Failure(err)
	}
	op.Complete()
	return nil
}

func (backend *Backend) release() {
	if backend.sem == nil {
		return
	}
	backend.sem.Release(1)
}

// New creates a new Backend.
func New(ctx context.Context, dsn string, options ...Option) *Backend {
	backend := &Backend{
		cfg:             getConfig(options...),
		dsn:             dsn,
		onRecordChange:  signal.New(),
		onServiceChange: signal.New(),
		component:       telemetry.NewComponent(ctx, zerolog.TraceLevel, "storage.postgres"),
	}
	backend.closeCtx, backend.close = context.WithCancel(ctx)

	go backend.doPeriodically(func(ctx context.Context) error {
		_, pool, err := backend.init(ctx)
		if err != nil {
			return err
		}

		if err = backend.acquire(ctx); err != nil {
			return err
		}
		defer backend.release()

		return deleteChangesBefore(ctx, pool, time.Now().Add(-backend.cfg.expiry))
	}, time.Minute)

	go backend.doPeriodically(func(ctx context.Context) error {
		_, pool, err := backend.init(ctx)
		if err != nil {
			return err
		}

		if err = backend.acquire(ctx); err != nil {
			return err
		}
		defer backend.release()

		rowCount, err := deleteExpiredServices(ctx, pool, time.Now())
		if err != nil {
			return err
		}
		if rowCount > 0 {
			err = signalServiceChange(ctx, pool)
			if err != nil {
				return err
			}
		}

		return nil
	}, backend.cfg.registryTTL/2)

	go backend.doPeriodically(func(ctx context.Context) error {
		return backend.listenForNotifications(ctx)
	}, time.Millisecond*100)

	go backend.doPeriodically(func(ctx context.Context) error {
		err := backend.ping(ctx)
		if err != nil {
			health.ReportError(health.StorageBackend, err, health.StrAttr("backend", "postgres"))
		} else {
			health.ReportOK(health.StorageBackend, health.StrAttr("backend", "postgres"))
		}
		return nil
	}, time.Minute)

	return backend
}

// Close closes the underlying database connection.
func (backend *Backend) Close() error {
	_, op := backend.component.Start(context.Background(), "Close")
	backend.mu.Lock()
	defer backend.mu.Unlock()

	backend.close()

	if backend.pool != nil {
		backend.pool.Close()
		backend.pool = nil
	}
	op.Complete()
	return nil
}

// Get gets a record from the database.
func (backend *Backend) Get(
	ctx context.Context,
	recordType, recordID string,
) (*databroker.Record, error) {
	ctx, op := backend.component.Start(ctx, "Get")
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel()

	_, conn, err := backend.init(ctx)
	if err != nil {
		return nil, op.Failure(err)
	}

	if err = backend.acquire(ctx); err != nil {
		return nil, op.Failure(err)
	}
	defer backend.release()

	record, err := getRecord(ctx, conn, recordType, recordID, lockModeNone)
	if err != nil {
		return nil, op.Failure(err)
	}
	op.Complete()
	return record, nil
}

// GetOptions returns the options for the given record type.
func (backend *Backend) GetOptions(
	ctx context.Context,
	recordType string,
) (*databroker.Options, error) {
	ctx, op := backend.component.Start(ctx, "GetOptions")
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel()

	_, conn, err := backend.init(ctx)
	if err != nil {
		return nil, op.Failure(err)
	}

	if err = backend.acquire(ctx); err != nil {
		return nil, op.Failure(err)
	}
	defer backend.release()

	opts, err := getOptions(ctx, conn, recordType)
	if err != nil {
		return nil, op.Failure(err)
	}
	op.Complete()
	return opts, nil
}

// Lease attempts to acquire a lease for the given name.
func (backend *Backend) Lease(
	ctx context.Context,
	leaseName, leaseID string,
	ttl time.Duration,
) (acquired bool, err error) {
	ctx, op := backend.component.Start(ctx, "Lease")
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel()

	_, conn, err := backend.init(ctx)
	if err != nil {
		return false, op.Failure(err)
	}

	if err = backend.acquire(ctx); err != nil {
		return false, op.Failure(err)
	}
	defer backend.release()

	leaseHolderID, err := maybeAcquireLease(ctx, conn, leaseName, leaseID, ttl)
	if err != nil {
		return false, op.Failure(err)
	}
	op.Complete()
	return leaseHolderID == leaseID, nil
}

// ListTypes lists the record types.
func (backend *Backend) ListTypes(ctx context.Context) ([]string, error) {
	ctx, op := backend.component.Start(ctx, "ListTypes")
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel()

	_, conn, err := backend.init(ctx)
	if err != nil {
		return nil, op.Failure(err)
	}

	if err = backend.acquire(ctx); err != nil {
		return nil, op.Failure(err)
	}
	defer backend.release()

	types, err := listTypes(ctx, conn)
	if err != nil {
		return nil, op.Failure(err)
	}
	op.Complete()
	return types, nil
}

// Put puts a record into Postgres.
func (backend *Backend) Put(
	ctx context.Context,
	records []*databroker.Record,
) (serverVersion uint64, err error) {
	ctx, op := backend.component.Start(ctx, "Put")
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel()

	serverVersion, pool, err := backend.init(ctx)
	if err != nil {
		return 0, op.Failure(err)
	}

	if err = backend.acquire(ctx); err != nil {
		return 0, op.Failure(err)
	}
	defer backend.release()

	now := timestamppb.Now()

	// add all the records
	recordTypes := map[string]struct{}{}
	for i, record := range records {
		recordTypes[record.GetType()] = struct{}{}

		record = dup(record)
		record.ModifiedAt = now
		err := putRecordAndChange(ctx, pool, record)
		if err != nil {
			return serverVersion, op.Failure(fmt.Errorf("storage/postgres: error saving record: %w", err))
		}
		records[i] = record
	}

	// enforce options for each record type
	for recordType := range recordTypes {
		options, err := getOptions(ctx, pool, recordType)
		if err != nil {
			return serverVersion, op.Failure(fmt.Errorf("storage/postgres: error getting options: %w", err))
		}
		err = enforceOptions(ctx, pool, recordType, options)
		if err != nil {
			return serverVersion, op.Failure(fmt.Errorf("storage/postgres: error enforcing options: %w", err))
		}
	}

	err = signalRecordChange(ctx, pool)
	if err != nil {
		return serverVersion, op.Failure(err)
	}
	op.Complete()
	return serverVersion, nil
}

// Patch updates specific fields of existing records in Postgres.
func (backend *Backend) Patch(
	ctx context.Context,
	records []*databroker.Record,
	fields *fieldmaskpb.FieldMask,
) (uint64, []*databroker.Record, error) {
	ctx, op := backend.component.Start(ctx, "Patch")
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel()

	serverVersion, pool, err := backend.init(ctx)
	if err != nil {
		return serverVersion, nil, op.Failure(err)
	}

	if err = backend.acquire(ctx); err != nil {
		return serverVersion, nil, op.Failure(err)
	}
	defer backend.release()

	patchedRecords := make([]*databroker.Record, 0, len(records))

	now := timestamppb.Now()

	for _, record := range records {
		record = dup(record)
		record.ModifiedAt = now
		err := patchRecord(ctx, pool, record, fields)
		if storage.IsNotFound(err) {
			continue
		} else if err != nil {
			err = fmt.Errorf("storage/postgres: error patching record %q of type %q: %w",
				record.GetId(), record.GetType(), err)
			return serverVersion, patchedRecords, op.Failure(err)
		}
		patchedRecords = append(patchedRecords, record)
	}

	err = signalRecordChange(ctx, pool)
	if err != nil {
		return serverVersion, patchedRecords, op.Failure(err)
	}
	op.Complete()
	return serverVersion, patchedRecords, nil
}

// SetOptions sets the options for the given record type.
func (backend *Backend) SetOptions(
	ctx context.Context,
	recordType string,
	options *databroker.Options,
) error {
	ctx, op := backend.component.Start(ctx, "SetOptions")
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel()

	_, conn, err := backend.init(ctx)
	if err != nil {
		return op.Failure(err)
	}

	if err = backend.acquire(ctx); err != nil {
		return op.Failure(err)
	}
	defer backend.release()

	err = setOptions(ctx, conn, recordType, options)
	if err != nil {
		return op.Failure(err)
	}
	op.Complete()
	return nil
}

// Sync syncs the records.
func (backend *Backend) Sync(
	ctx context.Context,
	recordType string,
	serverVersion, recordVersion uint64,
) (storage.RecordStream, error) {
	ctx, op := backend.component.Start(ctx, "Sync")
	// the original ctx will be used for the stream, this ctx used for pre-stream calls
	callCtx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel()

	currentServerVersion, _, err := backend.init(callCtx)
	if err != nil {
		return nil, op.Failure(err)
	}
	if currentServerVersion != serverVersion {
		return nil, op.Failure(storage.ErrInvalidServerVersion)
	}

	op.Complete()
	return newChangedRecordStream(ctx, backend, recordType, recordVersion), nil
}

// SyncLatest syncs the latest version of each record.
func (backend *Backend) SyncLatest(
	ctx context.Context,
	recordType string,
	expr storage.FilterExpression,
) (serverVersion, recordVersion uint64, stream storage.RecordStream, err error) {
	ctx, op := backend.component.Start(ctx, "SyncLatest")
	// the original ctx will be used for the stream, this ctx used for pre-stream calls
	callCtx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel()

	serverVersion, pool, err := backend.init(callCtx)
	if err != nil {
		return 0, 0, nil, op.Failure(err)
	}

	if err = backend.acquire(callCtx); err != nil {
		return 0, 0, nil, op.Failure(err)
	}
	defer backend.release()

	recordVersion, err = getLatestRecordVersion(callCtx, pool)
	if err != nil {
		return 0, 0, nil, op.Failure(err)
	}

	if recordType != "" {
		f := storage.EqualsFilterExpression{
			Fields: []string{"type"},
			Value:  recordType,
		}
		if expr != nil {
			expr = storage.AndFilterExpression{expr, f}
		} else {
			expr = f
		}
	}

	stream = newRecordStream(ctx, backend, expr)
	op.Complete()
	return serverVersion, recordVersion, stream, nil
}

func (backend *Backend) init(ctx context.Context) (serverVersion uint64, pool *pgxpool.Pool, err error) {
	backend.mu.RLock()
	serverVersion = backend.serverVersion
	pool = backend.pool
	backend.mu.RUnlock()

	if pool != nil {
		return serverVersion, pool, nil
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()

	// double-checked locking, might have already initialized, so just return
	serverVersion = backend.serverVersion
	pool = backend.pool
	if pool != nil {
		return serverVersion, pool, nil
	}

	config, err := ParseConfig(backend.dsn)
	if err != nil {
		return serverVersion, nil, err
	}

	if backend.cfg.tracerProvider != nil {
		config.ConnConfig.Tracer = otelpgx.NewTracer(
			otelpgx.WithTracerProvider(backend.cfg.tracerProvider))
	}

	pool, err = pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return serverVersion, nil, fmt.Errorf("error creating pgxpool: %w", err)
	}

	if backend.cfg.limitConcurrency && backend.sem == nil {
		weight := int64(config.MaxConns)
		if weight <= 0 {
			weight = math.MaxInt64
		}
		backend.sem = semaphore.NewWeighted(weight)
	}

	err = otelpgx.RecordStats(pool)
	if err != nil {
		return serverVersion, nil, fmt.Errorf("error recording stats: %w", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return serverVersion, nil, fmt.Errorf("error starting transaction: %w", err)
	}

	serverVersion, err = migrate(ctx, tx)
	if err != nil {
		_ = tx.Rollback(ctx)
		return serverVersion, nil, fmt.Errorf("error running migrations: %w", err)
	}

	err = tx.Commit(ctx)
	if err != nil {
		_ = tx.Rollback(ctx)
		return serverVersion, nil, fmt.Errorf("error committing transaction: %w", err)
	}

	backend.serverVersion = serverVersion
	backend.pool = pool
	return serverVersion, pool, nil
}

func (backend *Backend) doPeriodically(f func(ctx context.Context) error, dur time.Duration) {
	ctx := backend.closeCtx

	ticker := time.NewTicker(dur)
	defer ticker.Stop()

	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 0

	for {
		err := f(ctx)
		if err == nil {
			bo.Reset()
			select {
			case <-backend.closeCtx.Done():
				return
			case <-ticker.C:
			}
		} else {
			if !errors.Is(err, context.Canceled) {
				log.Ctx(ctx).Error().Err(err).Msg("storage/postgres")
			}
			select {
			case <-backend.closeCtx.Done():
				return
			case <-time.After(bo.NextBackOff()):
			}
		}
	}
}

func (backend *Backend) listenForNotifications(ctx context.Context) error {
	_, pool, err := backend.init(ctx)
	if err != nil {
		return fmt.Errorf("error initializing pool for notifications: %w", err)
	}

	poolConn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("error acquiring connection from pool for notifications: %w", err)
	}

	// hijack the connection so the pool can be left for short-lived queries
	// and so that LISTENs don't leak to other queries
	conn := poolConn.Hijack()
	defer conn.Close(ctx)

	for _, ch := range []string{recordChangeNotifyName, serviceChangeNotifyName} {
		_, err = conn.Exec(ctx, `LISTEN `+ch)
		if err != nil {
			return fmt.Errorf("error listening on channel %s for notifications: %w", ch, err)
		}
	}

	// for each notification broadcast the signal
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			// on error we'll close the connection to stop listening
			return fmt.Errorf("error receiving notification: %w", err)
		}

		switch n.Channel {
		case recordChangeNotifyName:
			backend.onRecordChange.Broadcast(ctx)
		case serviceChangeNotifyName:
			backend.onServiceChange.Broadcast(ctx)
		}
	}
}

func (backend *Backend) ping(ctx context.Context) error {
	_, pool, err := backend.init(ctx)
	if err != nil {
		return err
	}

	if err = backend.acquire(ctx); err != nil {
		return err
	}
	defer backend.release()

	return pool.Ping(ctx)
}

// ParseConfig parses a DSN into a pgxpool.Config.
func ParseConfig(dsn string) (*pgxpool.Config, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	config.ConnConfig.LookupFunc = lookup
	return config, nil
}

func lookup(ctx context.Context, host string) (addrs []string, err error) {
	addrs, err = net.DefaultResolver.LookupHost(ctx, host)
	// ignore no such host errors
	if e := new(net.DNSError); errors.As(err, &e) && e.IsNotFound {
		addrs = nil
		err = nil
	}
	return addrs, err
}
