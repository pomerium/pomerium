package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/pkg/contextutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

// Backend is a storage Backend implemented with Postgres.
type Backend struct {
	cfg             *config
	dsn             string
	onRecordChange  *signal.Signal
	onServiceChange *signal.Signal

	closeCtx context.Context
	close    context.CancelFunc

	mu            sync.RWMutex
	pool          *pgxpool.Pool
	serverVersion uint64
}

// New creates a new Backend.
func New(dsn string, options ...Option) *Backend {
	backend := &Backend{
		cfg:             getConfig(options...),
		dsn:             dsn,
		onRecordChange:  signal.New(),
		onServiceChange: signal.New(),
	}
	backend.closeCtx, backend.close = context.WithCancel(context.Background())

	go backend.doPeriodically(func(ctx context.Context) error {
		_, pool, err := backend.init(ctx)
		if err != nil {
			return err
		}

		return deleteChangesBefore(ctx, pool, time.Now().Add(-backend.cfg.expiry))
	}, time.Minute)

	go backend.doPeriodically(func(ctx context.Context) error {
		_, pool, err := backend.init(ctx)
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

		return nil
	}, backend.cfg.registryTTL/2)

	// listen for changes and broadcast them via signals
	for _, row := range []struct {
		signal  *signal.Signal
		channel string
	}{
		{backend.onRecordChange, recordChangeNotifyName},
		{backend.onServiceChange, serviceChangeNotifyName},
	} {
		sig, ch := row.signal, row.channel
		go backend.doPeriodically(func(ctx context.Context) error {
			_, pool, err := backend.init(backend.closeCtx)
			if err != nil {
				return err
			}

			conn, err := pool.Acquire(ctx)
			if err != nil {
				return err
			}
			defer conn.Release()

			_, err = conn.Exec(ctx, `LISTEN `+ch)
			if err != nil {
				return err
			}

			_, err = conn.Conn().WaitForNotification(ctx)
			if err != nil {
				return err
			}

			sig.Broadcast(ctx)

			return nil
		}, time.Millisecond*100)
	}

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

// Get gets a record from the database.
func (backend *Backend) Get(
	ctx context.Context,
	recordType, recordID string,
) (*databroker.Record, error) {
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel()

	_, conn, err := backend.init(ctx)
	if err != nil {
		return nil, err
	}

	return getRecord(ctx, conn, recordType, recordID, lockModeNone)
}

// GetOptions returns the options for the given record type.
func (backend *Backend) GetOptions(
	ctx context.Context,
	recordType string,
) (*databroker.Options, error) {
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel()

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
	defer cancel()

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
	defer cancel()

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
	defer cancel()

	serverVersion, pool, err := backend.init(ctx)
	if err != nil {
		return 0, err
	}

	now := timestamppb.Now()

	// add all the records
	recordTypes := map[string]struct{}{}
	for i, record := range records {
		recordTypes[record.GetType()] = struct{}{}

		record = dup(record)
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
	defer cancel()

	serverVersion, pool, err := backend.init(ctx)
	if err != nil {
		return serverVersion, nil, err
	}

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
			return serverVersion, patchedRecords, err
		}
		patchedRecords = append(patchedRecords, record)
	}

	err = signalRecordChange(ctx, pool)
	return serverVersion, patchedRecords, err
}

// SetOptions sets the options for the given record type.
func (backend *Backend) SetOptions(
	ctx context.Context,
	recordType string,
	options *databroker.Options,
) error {
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel()

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
) (storage.RecordStream, error) {
	// the original ctx will be used for the stream, this ctx used for pre-stream calls
	callCtx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel()

	currentServerVersion, _, err := backend.init(callCtx)
	if err != nil {
		return nil, err
	}
	if currentServerVersion != serverVersion {
		return nil, storage.ErrInvalidServerVersion
	}

	return newChangedRecordStream(ctx, backend, recordType, recordVersion), nil
}

// SyncLatest syncs the latest version of each record.
func (backend *Backend) SyncLatest(
	ctx context.Context,
	recordType string,
	expr storage.FilterExpression,
) (serverVersion, recordVersion uint64, stream storage.RecordStream, err error) {
	// the original ctx will be used for the stream, this ctx used for pre-stream calls
	callCtx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	defer cancel()

	serverVersion, pool, err := backend.init(callCtx)
	if err != nil {
		return 0, 0, nil, err
	}

	recordVersion, err = getLatestRecordVersion(callCtx, pool)
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

	stream = newRecordStream(ctx, backend, expr)
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

	pool, err = pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return serverVersion, nil, err
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return serverVersion, nil, err
	}

	serverVersion, err = migrate(ctx, tx)
	if err != nil {
		_ = tx.Rollback(ctx)
		return serverVersion, nil, err
	}

	err = tx.Commit(ctx)
	if err != nil {
		_ = tx.Rollback(ctx)
		return serverVersion, nil, err
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
				log.Error(ctx).Err(err).Msg("storage/postgres")
			}
			select {
			case <-backend.closeCtx.Done():
				return
			case <-time.After(bo.NextBackOff()):
			}
		}
	}
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
