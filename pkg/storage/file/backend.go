package file

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cockroachdb/pebble/v2"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/pomerium/pomerium/internal/signal"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

const batchSize = 64

// Backend implements a storage Backend backed by a pebble on-disk store.
type Backend struct {
	dsn            string
	onRecordChange *signal.Signal

	mu sync.RWMutex
	db *pebble.DB

	initOnce sync.Once
	initErr  error

	closeOnce sync.Once
	closeErr  error
	closeCtx  context.Context
	close     context.CancelFunc
}

// New creates a new Backend.
func New(dsn string) *Backend {
	backend := &Backend{
		dsn:            dsn,
		onRecordChange: signal.New(),
	}
	backend.closeCtx, backend.close = context.WithCancel(context.Background())

	return backend
}

// Close closes the backend.
func (backend *Backend) Close() error {
	err := backend.init()
	if err != nil {
		return fmt.Errorf("pebble: error initializing: %w", err)
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()

	backend.closeOnce.Do(func() {
		backend.close()
		err := backend.db.Close()
		if err != nil {
			backend.closeErr = fmt.Errorf("pebble: error closing: %w", err)
		}
	})
	return backend.closeErr
}

// Clean removes old data.
func (backend *Backend) Clean(
	ctx context.Context,
	options storage.CleanOptions,
) error {
	defer backend.onRecordChange.Broadcast(ctx)
	return backend.withReaderWriter(func(rw readerWriter) error {
		return clean(rw, options)
	})
}

// Get is used to retrieve a record.
func (backend *Backend) Get(
	_ context.Context,
	recordType, recordID string,
) (record *databrokerpb.Record, err error) {
	err = backend.withReader(func(r reader) error {
		var err error
		record, err = getRecord(r, recordType, recordID)
		return err
	})
	return record, err
}

// GetOptions gets the options for a type.
func (backend *Backend) GetOptions(
	_ context.Context,
	recordType string,
) (options *databrokerpb.Options, err error) {
	err = backend.withReader(func(r reader) error {
		var err error
		options, err = getOptions(r, recordType)
		return err
	})
	return options, err
}

// Lease acquires a lease, or renews an existing one. If the lease is acquired true is returned.
func (backend *Backend) Lease(
	_ context.Context,
	leaseName, leaseID string,
	ttl time.Duration,
) (acquired bool, err error) {
	err = backend.withReaderWriter(func(rw readerWriter) error {
		var err error
		acquired, err = lease(rw, leaseName, leaseID, ttl)
		return err
	})
	return acquired, err
}

// ListTypes lists all the known record types.
func (backend *Backend) ListTypes(
	_ context.Context,
) (recordTypes []string, err error) {
	err = backend.withReader(func(r reader) error {
		var err error
		recordTypes, err = listTypes(r)
		return err
	})
	return recordTypes, err
}

// Put is used to insert or update records.
func (backend *Backend) Put(
	ctx context.Context,
	records []*databrokerpb.Record,
) (serverVersion uint64, err error) {
	defer backend.onRecordChange.Broadcast(ctx)
	err = backend.withReaderWriter(func(rw readerWriter) error {
		var err error
		serverVersion, err = putRecords(rw, records)
		return err
	})
	return serverVersion, err
}

// Patch is used to update specific fields of existing records.
func (backend *Backend) Patch(
	ctx context.Context,
	records []*databrokerpb.Record,
	fields *fieldmaskpb.FieldMask,
) (serverVersion uint64, patchedRecords []*databrokerpb.Record, err error) {
	defer backend.onRecordChange.Broadcast(ctx)
	err = backend.withReaderWriter(func(rw readerWriter) error {
		var err error
		serverVersion, patchedRecords, err = patchRecords(rw, records, fields)
		return err
	})
	return serverVersion, patchedRecords, err
}

// SetOptions sets the options for a type.
func (backend *Backend) SetOptions(
	_ context.Context,
	recordType string,
	options *databrokerpb.Options,
) error {
	return backend.withReaderWriter(func(rw readerWriter) error {
		return setOptions(rw, recordType, options)
	})
}

// Sync syncs record changes after the specified version. If wait is set to
// true the record iterator will continue to receive records until the
// iterator or ctx is cancelled.
func (backend *Backend) Sync(
	ctx context.Context,
	recordType string,
	serverVersion, afterRecordVersion uint64,
	wait bool,
) storage.RecordIterator {
	return backend.iterateChangedRecords(ctx, recordType, serverVersion, afterRecordVersion, wait)
}

// SyncLatest syncs all the records.
func (backend *Backend) SyncLatest(
	ctx context.Context,
	recordType string,
	filter storage.FilterExpression,
) (serverVersion, recordVersion uint64, seq storage.RecordIterator, err error) {
	err = backend.withReader(func(r reader) error {
		var err error
		serverVersion, recordVersion, seq, err = backend.syncLatestLocked(ctx, r, recordType, filter)
		return err
	})
	return serverVersion, recordVersion, seq, err
}

func (backend *Backend) syncLatestLocked(
	ctx context.Context,
	r reader,
	recordType string,
	filter storage.FilterExpression,
) (serverVersion, recordVersion uint64, seq storage.RecordIterator, err error) {
	serverVersion, err = metadataKeySpace.getServerVersion(r)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("pebble: error reading server version: %w", err)
	}
	recordVersion, err = metadataKeySpace.getLatestRecordVersion(r)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("pebble: error reading record version: %w", err)
	}

	if recordType != "" {
		f := storage.EqualsFilterExpression{
			Fields: []string{"type"},
			Value:  recordType,
		}
		if filter != nil {
			filter = storage.AndFilterExpression{filter, f}
		} else {
			filter = f
		}
	}

	return serverVersion, recordVersion, backend.iterateLatestRecords(ctx, filter), nil
}
