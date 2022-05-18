package postgres

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

// Backend is a storage Backend implemented with Postgres.
type Backend struct {
	dsn      string
	onChange *signal.Signal

	mu            sync.RWMutex
	conn          *pgx.Conn
	serverVersion uint64
}

// NewBackend creates a new Backend.
func NewBackend(dsn string) *Backend {
	return &Backend{
		dsn:      dsn,
		onChange: signal.New(),
	}
}

// Close closes the underlying database connection.
func (backend *Backend) Close() error {
	backend.mu.Lock()
	defer backend.mu.Unlock()

	var err error
	if backend.conn != nil {
		err = backend.conn.Close(context.Background())
		backend.conn = nil
	}
	return err
}

// Get gets a record from the database.
func (backend *Backend) Get(
	ctx context.Context,
	recordType, recordID string,
) (*databroker.Record, error) {
	_, conn, err := backend.init(ctx)
	if err != nil {
		return nil, err
	}

	return getRecord(ctx, conn, recordType, recordID)
}

// GetOptions returns the options for the given record type.
func (backend *Backend) GetOptions(
	ctx context.Context,
	recordType string,
) (*databroker.Options, error) {
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

// Put puts a record into Postgres.
func (backend *Backend) Put(
	ctx context.Context,
	records []*databroker.Record,
) (serverVersion uint64, err error) {
	serverVersion, conn, err := backend.init(ctx)
	if err != nil {
		return 0, err
	}

	return serverVersion, conn.BeginFunc(ctx, func(tx pgx.Tx) error {
		now := timestamppb.Now()

		// add all the records
		recordTypes := map[string]struct{}{}
		for i, record := range records {
			recordTypes[record.GetType()] = struct{}{}

			record = dup(record)
			record.ModifiedAt = now
			err := putRecordChange(ctx, tx, record)
			if err != nil {
				return err
			}

			err = putRecord(ctx, tx, record)
			if err != nil {
				return err
			}
			records[i] = record
		}

		// enforce options for each record type
		for recordType := range recordTypes {
			options, err := getOptions(ctx, tx, recordType)
			if err != nil {
				return err
			}
			err = enforceOptions(ctx, tx, recordType, options)
			if err != nil {
				return err
			}
		}

		return nil
	})
}

// SetOptions sets the options for the given record type.
func (backend *Backend) SetOptions(
	ctx context.Context,
	recordType string,
	options *databroker.Options,
) error {
	_, conn, err := backend.init(ctx)
	if err != nil {
		return err
	}

	return setOptions(ctx, conn, recordType, options)
}

// Sync syncs the records.
func (backend *Backend) Sync(
	ctx context.Context,
	serverVersion, recordVersion uint64,
) (storage.RecordStream, error) {
	panic("Sync not implemented")
}

// SyncLatest syncs the latest version of each record.
func (backend *Backend) SyncLatest(
	ctx context.Context,
	recordType string,
	expr storage.FilterExpression,
) (serverVersion, recordVersion uint64, stream storage.RecordStream, err error) {
	serverVersion, conn, err := backend.init(ctx)
	if err != nil {
		return 0, 0, nil, err
	}

	recordVersion, err = getLatestRecordVersion(ctx, conn)
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

	stream1 := newRecordStream(ctx, backend, expr)
	stream2 := newChangedRecordStream(ctx, backend, recordVersion)
	stream = storage.NewConcatenatedRecordStream(stream1, stream2)
	return serverVersion, recordVersion, stream, nil
}

func (backend *Backend) init(ctx context.Context) (serverVersion uint64, conn *pgx.Conn, err error) {
	backend.mu.RLock()
	serverVersion = backend.serverVersion
	conn = backend.conn
	backend.mu.RUnlock()

	if conn != nil {
		return serverVersion, conn, nil
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()

	config, err := pgx.ParseConfig(backend.dsn)
	if err != nil {
		return serverVersion, nil, err
	}

	config.OnNotification = func(pc *pgconn.PgConn, n *pgconn.Notification) {
		log.Info(context.Background()).
			Str("address", pc.Conn().RemoteAddr().String()).
			Str("channel", n.Channel).
			Uint32("pid", n.PID).
			Msg("postgres: notification")
	}

	conn, err = pgx.ConnectConfig(context.Background(), config)
	if err != nil {
		return serverVersion, nil, err
	}

	err = conn.BeginFunc(ctx, func(tx pgx.Tx) error {
		var err error
		serverVersion, err = migrate(ctx, tx)
		return err
	})
	if err != nil {
		return serverVersion, nil, err
	}

	backend.serverVersion = serverVersion
	backend.conn = conn
	return serverVersion, conn, nil
}
