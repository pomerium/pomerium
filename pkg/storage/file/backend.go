package file

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cockroachdb/pebble/v2"
	"github.com/gaissmai/bart"
	"github.com/hashicorp/go-set/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/pkg/contextutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/iterutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

const batchSize = 64

// Backend implements a storage Backend backed by a pebble on-disk store.
type Backend struct {
	dsn              string
	onRecordChange   *signal.Signal
	onServiceChange  *signal.Signal
	iteratorCanceler contextutil.Canceler

	mu                    sync.RWMutex
	db                    *pebble.DB
	serverVersion         uint64
	earliestRecordVersion uint64
	latestRecordVersion   uint64
	options               map[string]*databrokerpb.Options
	recordCIDRIndex       *recordCIDRIndex
	registryServiceIndex  *registryServiceIndex

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
		dsn:              dsn,
		onRecordChange:   signal.New(),
		onServiceChange:  signal.New(),
		iteratorCanceler: contextutil.NewCanceler(),
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
	_ context.Context,
	options storage.CleanOptions,
) error {
	return backend.withReadWriteTransaction(func(tx *readWriteTransaction) error {
		return backend.cleanLocked(tx, options)
	})
}

// Clear removes all records from the storage backend.
func (backend *Backend) Clear(_ context.Context) error {
	return backend.withReadWriteTransaction(func(tx *readWriteTransaction) error {
		return backend.clearLocked(tx)
	})
}

// Get is used to retrieve a record.
func (backend *Backend) Get(
	_ context.Context,
	recordType, recordID string,
) (record *databrokerpb.Record, err error) {
	err = backend.withReadOnlyTransaction(func(tx readOnlyTransaction) error {
		var err error
		record, err = backend.getRecordLocked(tx, recordType, recordID)
		return err
	})
	return record, err
}

// GetCheckpoint gets the latest checkpoint.
func (backend *Backend) GetCheckpoint(
	_ context.Context,
) (serverVersion, recordVersion uint64, err error) {
	err = backend.withReadOnlyTransaction(func(tx readOnlyTransaction) error {
		var err error
		serverVersion, recordVersion, err = backend.getCheckpointLocked(tx)
		return err
	})
	return serverVersion, recordVersion, err
}

// GetOptions gets the options for a type.
func (backend *Backend) GetOptions(
	_ context.Context,
	recordType string,
) (options *databrokerpb.Options, err error) {
	err = backend.withReadOnlyTransaction(func(_ readOnlyTransaction) error {
		options = backend.getOptionsLocked(recordType)
		return nil
	})
	return options, err
}

// Lease acquires a lease, or renews an existing one. If the lease is acquired true is returned.
func (backend *Backend) Lease(
	_ context.Context,
	leaseName, leaseID string,
	ttl time.Duration,
) (acquired bool, err error) {
	err = backend.withReadWriteTransaction(func(tx *readWriteTransaction) error {
		var err error
		acquired, err = backend.leaseLocked(tx, leaseName, leaseID, ttl)
		return err
	})
	return acquired, err
}

// ListTypes lists all the known record types.
func (backend *Backend) ListTypes(
	_ context.Context,
) (recordTypes []string, err error) {
	err = backend.withReadOnlyTransaction(func(tx readOnlyTransaction) error {
		var err error
		recordTypes, err = backend.listTypesLocked(tx)
		return err
	})
	return recordTypes, err
}

// Put is used to insert or update records.
func (backend *Backend) Put(
	ctx context.Context,
	records []*databrokerpb.Record,
) (serverVersion uint64, err error) {
	err = backend.withReadWriteTransaction(func(tx *readWriteTransaction) error {
		tx.onCommit(func() { backend.onRecordChange.Broadcast(ctx) })
		var err error
		serverVersion = backend.serverVersion
		err = backend.putRecordsLocked(tx, records)
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
	err = backend.withReadWriteTransaction(func(tx *readWriteTransaction) error {
		tx.onCommit(func() { backend.onRecordChange.Broadcast(ctx) })
		var err error
		serverVersion = backend.serverVersion
		patchedRecords, err = backend.patchRecordsLocked(tx, records, fields)
		return err
	})
	return serverVersion, patchedRecords, err
}

func (backend *Backend) SetCheckpoint(
	_ context.Context,
	serverVersion uint64,
	recordVersion uint64,
) error {
	return backend.withReadWriteTransaction(func(tx *readWriteTransaction) error {
		return backend.setCheckpointLocked(tx, serverVersion, recordVersion)
	})
}

// SetOptions sets the options for a type.
func (backend *Backend) SetOptions(
	_ context.Context,
	recordType string,
	options *databrokerpb.Options,
) error {
	return backend.withReadWriteTransaction(func(tx *readWriteTransaction) error {
		return backend.setOptionsLocked(tx, recordType, options)
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
	err = backend.withReadOnlyTransaction(func(_ readOnlyTransaction) error {
		var err error
		serverVersion, recordVersion, seq, err = backend.syncLatestLocked(ctx, recordType, filter)
		return err
	})
	return serverVersion, recordVersion, seq, err
}

// Versions returns the storage backend versions.
func (backend *Backend) Versions(_ context.Context) (serverVersion, earliestRecordVersion, latestRecordVersion uint64, err error) {
	err = backend.withReadOnlyTransaction(func(tx readOnlyTransaction) error {
		var err error
		serverVersion, earliestRecordVersion, latestRecordVersion, err = backend.versionsLocked(tx)
		return err
	})
	return serverVersion, earliestRecordVersion, latestRecordVersion, err
}

func (backend *Backend) cleanLocked(
	rw readerWriter,
	options storage.CleanOptions,
) error {
	// iterate over the record changes, deleting any before RemoveRecordChangesBefore
	// always keep at least one record at the end so that we can track version numbers
	for record, err := range iterutil.SkipLastWithError(recordChangeKeySpace.iterate(rw, 0), 1) {
		if err != nil {
			return fmt.Errorf("pebble: error iterating over record changes: %w", err)
		}

		if !record.GetModifiedAt().AsTime().Before(options.RemoveRecordChangesBefore) {
			break
		}

		err = recordChangeKeySpace.delete(rw, record.GetVersion())
		if err != nil {
			return fmt.Errorf("pebble: error deleting record change: %w", err)
		}
		err = recordChangeIndexByTypeKeySpace.delete(rw, record.GetType(), record.GetVersion())
		if err != nil {
			return fmt.Errorf("pebble: error deleting record change index by type: %w", err)
		}

		// this record was deleted, so only allow queries for records with larger version numbers
		backend.earliestRecordVersion = max(backend.earliestRecordVersion, record.GetVersion()+1)
	}

	return nil
}

func (backend *Backend) clearLocked(
	rw readerWriter,
) error {
	newServerVersion := cryptutil.NewRandomUInt64()
	err := errors.Join(
		optionsKeySpace.deleteAll(rw),
		recordKeySpace.deleteAll(rw),
		recordIndexByTypeVersionKeySpace.deleteAll(rw),
		recordChangeKeySpace.deleteAll(rw),
		recordChangeIndexByTypeKeySpace.deleteAll(rw),
		metadataKeySpace.setServerVersion(rw, newServerVersion),
		metadataKeySpace.setCheckpointServerVersion(rw, 0),
		metadataKeySpace.setCheckpointRecordVersion(rw, 0),
	)
	if err != nil {
		return fmt.Errorf("pebble: error clearing data: %w", err)
	}

	backend.serverVersion = newServerVersion
	clear(backend.options)
	backend.earliestRecordVersion = 0
	backend.latestRecordVersion = 0
	backend.recordCIDRIndex.table = bart.Table[[]recordCIDRNode]{}
	backend.iteratorCanceler.Cancel(nil)

	return nil
}

func (backend *Backend) deleteRecordLocked(
	rw readerWriter,
	recordType, recordID string,
) error {
	record, err := recordKeySpace.get(rw, recordType, recordID)
	if isNotFound(err) {
		// doesn't exist, so ignore
		return nil
	} else if err != nil {
		return fmt.Errorf("pebble: error getting record: %w", err)
	}

	// remove the record
	err = recordKeySpace.delete(rw, recordType, recordID)
	if err != nil {
		return fmt.Errorf("pebble: error deleting record: %w", err)
	}

	err = recordIndexByTypeVersionKeySpace.delete(rw, recordType, record.GetVersion())
	if err != nil {
		return fmt.Errorf("pebble: error deleting record index by type version: %w", err)
	}

	if prefix := storage.GetRecordIndexCIDR(record.GetData()); prefix != nil {
		backend.recordCIDRIndex.delete(recordCIDRNode{recordType: record.GetType(), recordID: record.GetId(), prefix: *prefix})
	}

	backend.latestRecordVersion++
	record.ModifiedAt = timestamppb.Now()
	record.DeletedAt = timestamppb.Now()
	record.Version = backend.latestRecordVersion

	// add the record change
	err = recordChangeKeySpace.set(rw, record)
	if err != nil {
		return fmt.Errorf("pebble: error setting record change: %w", err)
	}

	err = recordChangeIndexByTypeKeySpace.set(rw, record.GetType(), record.GetVersion())
	if err != nil {
		return fmt.Errorf("pebble: error setting record change index by type: %w", err)
	}

	return nil
}

func (backend *Backend) enforceOptionsLocked(
	rw readerWriter,
	recordType string,
) error {
	options, ok := backend.options[recordType]
	if !ok {
		// no options defined, nothing to do
		return nil
	}

	// if capacity isn't set, there's nothing to do
	if options.Capacity == nil {
		return nil
	}

	var cnt uint64
	for recordID, err := range recordIndexByTypeVersionKeySpace.iterateIDsReversed(rw, recordType) {
		if err != nil {
			return fmt.Errorf("pebble: error iterating over record index by type version: %w", err)
		}
		cnt++
		if cnt > options.GetCapacity() {
			err = backend.deleteRecordLocked(rw, recordType, recordID)
			if err != nil {
				return fmt.Errorf("pebble: error enforcing options: %w", err)
			}
		}
	}

	return nil
}

func (backend *Backend) getCheckpointLocked(
	r reader,
) (serverVersion, recordVersion uint64, err error) {
	serverVersion, err = metadataKeySpace.getCheckpointServerVersion(r)
	if err != nil {
		return 0, 0, err
	}
	recordVersion, err = metadataKeySpace.getCheckpointRecordVersion(r)
	if err != nil {
		return 0, 0, err
	}
	return serverVersion, recordVersion, err
}

func (backend *Backend) getOptionsLocked(recordType string) *databrokerpb.Options {
	options, ok := backend.options[recordType]
	if !ok {
		options = new(databrokerpb.Options)
	}
	return options
}

func (backend *Backend) getRecordLocked(
	r reader,
	recordType, recordID string,
) (*databrokerpb.Record, error) {
	record, err := recordKeySpace.get(r, recordType, recordID)
	if isNotFound(err) {
		err = storage.ErrNotFound
	} else if err != nil {
		err = fmt.Errorf("pebble: error getting record: %w", err)
	}
	if err != nil {
		return nil, err
	}
	return record, err
}

func (backend *Backend) leaseLocked(
	rw readerWriter,
	leaseName, leaseID string,
	ttl time.Duration,
) (bool, error) {
	// get the current lease
	currentLeaseID, expiresAt, err := leaseKeySpace.get(rw, leaseName)
	if isNotFound(err) {
		// lease doesn't exist yet, so acquire the lease
	} else if err != nil {
		return false, fmt.Errorf("pebble: error getting lease: %w", err)
	} else if currentLeaseID == leaseID || expiresAt.Before(time.Now()) {
		// leaes is either for this id, or has expired, so acquire the lease
	} else {
		// don't acquire the lease because someone else has it
		return false, nil
	}
	err = leaseKeySpace.set(rw, leaseName, leaseID, time.Now().Add(ttl))
	if err != nil {
		return false, fmt.Errorf("pebble: error setting lease: %w", err)
	}

	return true, err
}

func (backend *Backend) listLatestRecordsLocked(
	r reader,
	recordType string,
	filter storage.FilterExpression,
) ([]*databrokerpb.Record, error) {
	var records []*databrokerpb.Record
	for record, err := range backend.iterateRecordsForFilterLocked(r, recordType, filter) {
		if err != nil {
			return nil, fmt.Errorf("pebble: error iterating over records: %w", err)
		}
		if recordMatches(record, filter) {
			records = append(records, record)
		}
	}
	return records, nil
}

func (backend *Backend) listTypesLocked(
	r reader,
) ([]string, error) {
	var recordTypes []string
	for recordType, err := range recordKeySpace.iterateTypes(r) {
		if err != nil {
			return nil, fmt.Errorf("error iterating record types from pebble: %w", err)
		}
		recordTypes = append(recordTypes, recordType)
	}
	return recordTypes, nil
}

func (backend *Backend) patchRecordLocked(
	rw readerWriter,
	record *databrokerpb.Record,
	fields *fieldmaskpb.FieldMask,
) error {
	existing, err := recordKeySpace.get(rw, record.GetType(), record.GetId())
	if err != nil {
		return fmt.Errorf("pebble: error getting existing record: %w", err)
	}

	err = storage.PatchRecord(existing, record, fields)
	if err != nil {
		return fmt.Errorf("pebble: error patching record: %w", err)
	}

	return backend.updateRecordLocked(rw, record)
}

func (backend *Backend) patchRecordsLocked(
	rw readerWriter,
	records []*databrokerpb.Record,
	fields *fieldmaskpb.FieldMask,
) (patchedRecords []*databrokerpb.Record, err error) {
	// update records
	// keep track of each record type in the list so we can enforce options
	recordTypes := set.New[string](len(records))
	patchedRecords = make([]*databrokerpb.Record, 0, len(records))
	for _, record := range records {
		recordTypes.Insert(record.GetType())
		record = proto.CloneOf(record)
		err = backend.patchRecordLocked(rw, record, fields)
		if isNotFound(err) {
			continue
		} else if err != nil {
			return nil, fmt.Errorf("pebble: error patching record (type=%s id=%s): %w",
				record.GetType(), record.GetId(), err)
		}
		patchedRecords = append(patchedRecords, record)
	}

	// enforce options
	for recordType := range recordTypes.Items() {
		err = backend.enforceOptionsLocked(rw, recordType)
		if err != nil {
			return nil, fmt.Errorf("pebble: error enforcing options (type=%s): %w",
				recordType, err)
		}
	}

	return patchedRecords, err
}

func (backend *Backend) putRecordsLocked(
	rw readerWriter,
	records []*databrokerpb.Record,
) (err error) {
	// update records
	// keep track of each record type in the list so we can enforce options
	recordTypes := set.New[string](len(records))
	for i := range records {
		recordTypes.Insert(records[i].GetType())
		records[i] = proto.CloneOf(records[i])
		err = backend.updateRecordLocked(rw, records[i])
		if err != nil {
			return fmt.Errorf("pebble: error updating record (type=%s id=%s): %w",
				records[i].GetType(), records[i].GetId(), err)
		}
	}

	// enforce options
	for recordType := range recordTypes.Items() {
		err = backend.enforceOptionsLocked(rw, recordType)
		if err != nil {
			return fmt.Errorf("pebble: error enforcing options (type=%s): %w",
				recordType, err)
		}
	}

	return err
}

func (backend *Backend) setCheckpointLocked(
	rw readerWriter,
	serverVersion uint64,
	recordVersion uint64,
) error {
	return errors.Join(
		metadataKeySpace.setCheckpointServerVersion(rw, serverVersion),
		metadataKeySpace.setCheckpointRecordVersion(rw, recordVersion),
	)
}

func (backend *Backend) setOptionsLocked(
	rw readerWriter,
	recordType string,
	options *databrokerpb.Options,
) error {
	var err error
	// if the options are empty, just delete them since we will return empty options on not found
	if proto.Equal(options, new(databrokerpb.Options)) {
		err = optionsKeySpace.delete(rw, recordType)
		delete(backend.options, recordType)
	} else {
		err = optionsKeySpace.set(rw, recordType, options)
		backend.options[recordType] = proto.CloneOf(options)
	}
	if err != nil {
		return fmt.Errorf("pebble: error updating options: %w", err)
	}
	return nil
}

func (backend *Backend) updateRecordLocked(
	rw readerWriter,
	record *databrokerpb.Record,
) error {
	if record.GetDeletedAt() != nil {
		return backend.deleteRecordLocked(rw, record.GetType(), record.GetId())
	}

	existing, err := recordKeySpace.get(rw, record.GetType(), record.GetId())
	if isNotFound(err) {
		// nothing to do
	} else if err != nil {
		return fmt.Errorf("pebble: error getting existing record: %w", err)
	} else {
		err = recordIndexByTypeVersionKeySpace.delete(rw, existing.GetType(), existing.GetVersion())
		if err != nil {
			return fmt.Errorf("pebble: error updating record index by type version: %w", err)
		}

		if prefix := storage.GetRecordIndexCIDR(existing.GetData()); prefix != nil {
			backend.recordCIDRIndex.delete(recordCIDRNode{recordType: existing.GetType(), recordID: existing.GetId(), prefix: *prefix})
		}
	}

	backend.latestRecordVersion++
	record.ModifiedAt = timestamppb.Now()
	record.Version = backend.latestRecordVersion

	err = recordChangeKeySpace.set(rw, record)
	if err != nil {
		return fmt.Errorf("pebble: error setting record change: %w", err)
	}

	err = recordChangeIndexByTypeKeySpace.set(rw, record.GetType(), record.GetVersion())
	if err != nil {
		return fmt.Errorf("pebble: error setting record change by type: %w", err)
	}

	err = recordKeySpace.set(rw, record)
	if err != nil {
		return fmt.Errorf("pebble: error setting record: %w", err)
	}

	err = recordIndexByTypeVersionKeySpace.set(rw, record.GetType(), record.GetId(), record.GetVersion())
	if err != nil {
		return fmt.Errorf("pebble: error setting record index by type version: %w", err)
	}

	if prefix := storage.GetRecordIndexCIDR(record.GetData()); prefix != nil {
		backend.recordCIDRIndex.add(recordCIDRNode{recordType: record.GetType(), recordID: record.GetId(), prefix: *prefix})
	}

	return nil
}

func (backend *Backend) syncLatestLocked(
	ctx context.Context,
	recordType string,
	filter storage.FilterExpression,
) (serverVersion, recordVersion uint64, seq storage.RecordIterator, err error) {
	return backend.serverVersion, backend.latestRecordVersion, backend.iterateLatestRecords(ctx, recordType, filter), nil
}

func (backend *Backend) versionsLocked(
	_ reader,
) (serverVersion, earliestRecordVersion, latestRecordVersion uint64, err error) {
	return backend.serverVersion, backend.earliestRecordVersion, backend.latestRecordVersion, nil
}
