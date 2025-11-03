package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/exaring/otelpgx"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/pkg/contextutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/storage"
)

// Backend is a storage Backend implemented with Postgres.
type Backend struct {
	cfg              *config
	dsn              string
	onRecordChange   *signal.Signal
	onServiceChange  *signal.Signal
	iteratorCanceler contextutil.Canceler

	closeCtx context.Context
	close    context.CancelFunc

	mu            sync.RWMutex
	pool          *pgxpool.Pool
	serverVersion uint64
}

// New creates a new Backend.
func New(ctx context.Context, dsn string, options ...Option) *Backend {
	backend := &Backend{
		cfg:              getConfig(options...),
		dsn:              dsn,
		onRecordChange:   signal.New(),
		onServiceChange:  signal.New(),
		iteratorCanceler: contextutil.NewCanceler(),
	}
	backend.closeCtx, backend.close = context.WithCancel(ctx)

	go backend.doOnceAndPeriodically(func(ctx context.Context) error {
		_, pool, err := backend.init(ctx)
		if errors.Is(err, context.Canceled) {
			return nil
		}
		if err != nil {
			return err
		}
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
		if err != nil {
			health.ReportError(health.StorageBackendCleanup, err, backend.healthAttrs()...)
		} else {
			health.ReportRunning(health.StorageBackendCleanup, backend.healthAttrs()...)
		}
		return err
	}, backend.cfg.registryTTL/2)

	go backend.doOnceAndPeriodically(func(ctx context.Context) error {
		err := backend.listenForNotifications(ctx)
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}, time.Millisecond*100)

	go backend.doOnceAndPeriodically(func(ctx context.Context) error {
		err := backend.ping(ctx)
		// ignore canceled errors
		if errors.Is(err, context.Canceled) {
			return nil
		}

		if err != nil {
			health.ReportError(health.StorageBackend, err, backend.healthAttrs()...)
		} else {
			health.ReportRunning(health.StorageBackend, backend.healthAttrs()...)
		}
		return nil
	}, time.Minute)

	return backend
}

// Close closes the underlying database connection.
func (backend *Backend) Close() error {
	backend.mu.Lock()
	defer backend.mu.Unlock()

	backend.close()

	if backend.pool != nil {
		backend.pool.Close()
		backend.pool = nil
	}
	return nil
}

// Clean removes all changes before the given cutoff.
func (backend *Backend) Clean(ctx context.Context, options storage.CleanOptions) error {
	_, pool, err := backend.init(ctx)
	if err != nil {
		return err
	}

	return deleteChangesBefore(ctx, pool, options.RemoveRecordChangesBefore)
}

// Clear removes all records from the storage backend.
func (backend *Backend) Clear(ctx context.Context) error {
	_, pool, err := backend.init(ctx)
	if err != nil {
		return err
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()

	newServerVersion := uint64(cryptutil.NewRandomUInt32())
	err = clearRecords(ctx, pool, newServerVersion)
	if err != nil {
		return err
	}
	backend.serverVersion = newServerVersion
	backend.iteratorCanceler.Cancel(nil)
	return nil
}

// Get gets a record from the database.
func (backend *Backend) Get(
	ctx context.Context,
	recordType, recordID string,
) (*databroker.Record, error) {
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel(nil)

	_, conn, err := backend.init(ctx)
	if err != nil {
		return nil, err
	}

	return getRecord(ctx, conn, recordType, recordID, lockModeNone)
}

// GetCheckpoint gets the latest checkpoint.
func (backend *Backend) GetCheckpoint(
	ctx context.Context,
) (serverVersion, recordVersion uint64, err error) {
	_, pool, err := backend.init(ctx)
	if err != nil {
		return 0, 0, err
	}
	return getCheckpoint(ctx, pool)
}

// GetOptions returns the options for the given record type.
func (backend *Backend) GetOptions(
	ctx context.Context,
	recordType string,
) (*databroker.Options, error) {
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel(nil)

	_, conn, err := backend.init(ctx)
	if err != nil {
		return nil, err
	}

	return getOptions(ctx, conn, recordType)
}

// Lease attempts to acquire a lease for the given name.
func (backend *Backend) Lease(
	ctx context.Context,
	leaseName, leaseID string,
	ttl time.Duration,
) (acquired bool, err error) {
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel(nil)

	_, conn, err := backend.init(ctx)
	if err != nil {
		return false, err
	}

	leaseHolderID, err := maybeAcquireLease(ctx, conn, leaseName, leaseID, ttl)
	if err != nil {
		return false, err
	}

	return leaseHolderID == leaseID, nil
}

// ListTypes lists the record types.
func (backend *Backend) ListTypes(ctx context.Context) ([]string, error) {
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel(nil)

	_, conn, err := backend.init(ctx)
	if err != nil {
		return nil, err
	}

	return listTypes(ctx, conn)
}

// Put puts a record into Postgres.
func (backend *Backend) Put(
	ctx context.Context,
	records []*databroker.Record,
) (serverVersion uint64, err error) {
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel(nil)

	serverVersion, pool, err := backend.init(ctx)
	if err != nil {
		return 0, err
	}

	now := timestamppb.Now()

	// add all the records
	recordTypes := map[string]struct{}{}
	for i, record := range records {
		recordTypes[record.GetType()] = struct{}{}

		record = proto.CloneOf(record)
		record.ModifiedAt = now
		err := putRecordAndChange(ctx, pool, record)
		if err != nil {
			return serverVersion, fmt.Errorf("storage/postgres: error saving record: %w", err)
		}
		records[i] = record
	}

	// enforce options for each record type
	for recordType := range recordTypes {
		options, err := getOptions(ctx, pool, recordType)
		if err != nil {
			return serverVersion, fmt.Errorf("storage/postgres: error getting options: %w", err)
		}
		err = enforceOptions(ctx, pool, recordType, options)
		if err != nil {
			return serverVersion, fmt.Errorf("storage/postgres: error enforcing options: %w", err)
		}
	}

	err = signalRecordChange(ctx, pool)
	return serverVersion, err
}

// Patch updates specific fields of existing records in Postgres.
func (backend *Backend) Patch(
	ctx context.Context,
	records []*databroker.Record,
	fields *fieldmaskpb.FieldMask,
) (uint64, []*databroker.Record, error) {
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel(nil)

	serverVersion, pool, err := backend.init(ctx)
	if err != nil {
		return serverVersion, nil, err
	}

	patchedRecords := make([]*databroker.Record, 0, len(records))

	now := timestamppb.Now()

	for _, record := range records {
		record = proto.CloneOf(record)
		record.ModifiedAt = now
		err := patchRecord(ctx, pool, record, fields)
		if storage.IsNotFound(err) {
			continue
		} else if err != nil {
			err = fmt.Errorf("storage/postgres: error patching record %q of type %q: %w",
				record.GetId(), record.GetType(), err)
			return serverVersion, patchedRecords, err
		}
		patchedRecords = append(patchedRecords, record)
	}

	err = signalRecordChange(ctx, pool)
	return serverVersion, patchedRecords, err
}

// SetCheckpoint sets the latest checkpoint.
func (backend *Backend) SetCheckpoint(
	ctx context.Context,
	serverVersion, recordVersion uint64,
) error {
	_, pool, err := backend.init(ctx)
	if err != nil {
		return err
	}
	return setCheckpoint(ctx, pool, serverVersion, recordVersion)
}

// SetOptions sets the options for the given record type.
func (backend *Backend) SetOptions(
	ctx context.Context,
	recordType string,
	options *databroker.Options,
) error {
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel(nil)

	_, conn, err := backend.init(ctx)
	if err != nil {
		return err
	}

	return setOptions(ctx, conn, recordType, options)
}

// Sync syncs the records.
func (backend *Backend) Sync(
	ctx context.Context,
	recordType string,
	serverVersion, recordVersion uint64,
	wait bool,
) storage.RecordIterator {
	return backend.iterateChangedRecords(ctx, recordType, serverVersion, recordVersion, wait)
}

// SyncLatest syncs the latest version of each record.
func (backend *Backend) SyncLatest(
	ctx context.Context,
	recordType string,
	expr storage.FilterExpression,
) (serverVersion, recordVersion uint64, seq storage.RecordIterator, err error) {
	// the original ctx will be used for the stream, this ctx used for pre-stream calls
	callCtx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel(nil)

	serverVersion, pool, err := backend.init(callCtx)
	if err != nil {
		return 0, 0, nil, err
	}

	_, recordVersion, err = getRecordVersionRange(callCtx, pool)
	if err != nil {
		return 0, 0, nil, err
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
	return serverVersion, recordVersion, backend.iterateLatestRecords(ctx, expr), nil
}

// Versions returns the versions of the storage backend.
func (backend *Backend) Versions(ctx context.Context) (serverVersion, earliestRecordVersion, latestRecordVersion uint64, err error) {
	serverVersion, pool, err := backend.init(ctx)
	if err != nil {
		return 0, 0, 0, err
	}

	earliestRecordVersion, latestRecordVersion, err = getRecordVersionRange(ctx, pool)
	if err != nil {
		return 0, 0, 0, err
	}

	return serverVersion, earliestRecordVersion, latestRecordVersion, nil
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

	config, err := pgxpool.ParseConfig(backend.dsn)
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

func (backend *Backend) doOnceAndPeriodically(f func(ctx context.Context) error, dur time.Duration) {
	ctx := backend.closeCtx
	if err := f(ctx); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("storage/postgres")
	}
	backend.doPeriodically(f, dur)
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

	return pool.Ping(ctx)
}

func (backend *Backend) healthAttrs() []health.Attr {
	return []health.Attr{{Key: "backend", Value: "postgres"}}
}
