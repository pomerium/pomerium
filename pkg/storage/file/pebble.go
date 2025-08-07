package file

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net/url"
	"slices"
	"time"

	"github.com/cockroachdb/pebble/v2"
	"github.com/hashicorp/go-set/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/pebbleutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

type (
	reader interface {
		pebble.Reader
	}
	writer interface {
		pebble.Writer
	}
	readerWriter interface {
		reader
		writer
	}
)

func (backend *Backend) init() error {
	backend.initOnce.Do(func() {
		u, err := url.Parse(backend.dsn)
		if err != nil {
			backend.initErr = fmt.Errorf("pebble: invalid dsn, expected url: %w", err)
			return
		}

		switch u.Scheme {
		case "memory":
			backend.db = pebbleutil.MustOpenMemory(nil)
		case "file":
			backend.db, err = pebbleutil.Open(u.Path, nil)
			if err != nil {
				backend.initErr = fmt.Errorf("pebble: error opening database at %s: %w", u.Path, err)
				return
			}
		}

		err = migrate(backend.db)
		if err != nil {
			backend.initErr = fmt.Errorf("pebble: error migrating database: %w", err)
			return
		}

		backend.serverVersion, err = metadataKeySpace.getServerVersion(backend.db)
		if err != nil {
			backend.initErr = fmt.Errorf("pebble: error getting server version: %w", err)
			return
		}

		err = backend.initIndices()
		if err != nil {
			backend.initErr = fmt.Errorf("pebble: error initializing indices: %w", err)
			return
		}
	})
	return backend.initErr
}

func (backend *Backend) initIndices() error {
	batch := backend.db.NewIndexedBatch()
	now := time.Now()

	backend.registryServiceIndex = newRegistryServiceIndex()
	for node, err := range registryServiceKeySpace.iterate(backend.db) {
		if err != nil {
			return fmt.Errorf("pebble: error iterating over registry services: %w", err)
		}
		if node.expiresAt.Before(now) {
			err = registryServiceKeySpace.delete(batch, node.kind, node.endpoint)
			if err != nil {
				return fmt.Errorf("pebble: error deleting expired registry service: %w", err)
			}
		} else {
			backend.registryServiceIndex.add(&registry.Service{Kind: node.kind, Endpoint: node.endpoint}, now, node.expiresAt.Sub(now))
		}
	}

	err := batch.Commit(nil)
	if err != nil {
		return fmt.Errorf("pebble: error committing changes: %w", err)
	}

	return nil
}

type readOnlyTransaction struct {
	reader
}

func (backend *Backend) withReadOnlyTransaction(fn func(tx readOnlyTransaction) error) error {
	err := backend.init()
	if err != nil {
		return fmt.Errorf("pebble: error initializing: %w", err)
	}

	backend.mu.RLock()
	defer backend.mu.RUnlock()

	select {
	case <-backend.closeCtx.Done():
		return context.Cause(backend.closeCtx)
	default:
	}

	err = fn(readOnlyTransaction{backend.db})

	return err
}

type readWriteTransaction struct {
	*pebble.Batch

	onCommitCallbacks []func()
}

func (tx *readWriteTransaction) onCommit(callback func()) {
	tx.onCommitCallbacks = append(tx.onCommitCallbacks, callback)
}

func (backend *Backend) withReadWriteTransaction(fn func(tx *readWriteTransaction) error) error {
	err := backend.init()
	if err != nil {
		return fmt.Errorf("pebble: error initializing: %w", err)
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()

	select {
	case <-backend.closeCtx.Done():
		return context.Cause(backend.closeCtx)
	default:
	}

	batch := backend.db.NewIndexedBatch()

	tx := &readWriteTransaction{Batch: batch}
	err = fn(tx)
	if err != nil {
		_ = batch.Close()
		return err
	}

	err = batch.Commit(nil)
	if err != nil {
		return fmt.Errorf("pebble: error committing: %w", err)
	}

	for _, f := range slices.Backward(tx.onCommitCallbacks) {
		f()
	}

	return err
}

func clean(
	rw readerWriter,
	options storage.CleanOptions,
) error {
	earliestRecordVersion, err := metadataKeySpace.getEarliestRecordVersion(rw)
	if err != nil {
		return fmt.Errorf("pebble: error getting earliest record version: %w", err)
	}

	for record, err := range recordChangeKeySpace.iterate(rw, 0) {
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

		earliestRecordVersion = max(earliestRecordVersion, record.GetVersion()+1)
	}

	// set the earliest record version since we are removing changes
	err = metadataKeySpace.setEarliestRecordVersion(rw, earliestRecordVersion)
	if err != nil {
		return fmt.Errorf("pebble: error setting earliest record version: %w", err)
	}

	return nil
}

func deleteRecord(
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

	latestRecordVersion, err := metadataKeySpace.getLatestRecordVersion(rw)
	if err != nil {
		return fmt.Errorf("pebble: error getting latest record version: %w", err)
	}
	latestRecordVersion++

	record.ModifiedAt = timestamppb.Now()
	record.DeletedAt = timestamppb.Now()
	record.Version = latestRecordVersion

	// add the record change
	err = recordChangeKeySpace.set(rw, record)
	if err != nil {
		return fmt.Errorf("pebble: error setting record change: %w", err)
	}

	err = recordChangeIndexByTypeKeySpace.set(rw, record.GetType(), record.GetVersion())
	if err != nil {
		return fmt.Errorf("pebble: error setting record change index by type: %w", err)
	}

	err = metadataKeySpace.setLatestRecordVersion(rw, latestRecordVersion)
	if err != nil {
		return fmt.Errorf("pebble: error setting latest record version: %w", err)
	}

	return nil
}

func enforceOptions(
	rw readerWriter,
	recordType string,
) error {
	options, err := optionsKeySpace.get(rw, recordType)
	if isNotFound(err) {
		// no options defined, nothing to do
		return nil
	} else if err != nil {
		return fmt.Errorf("pebble: error getting options: %w", err)
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
			err = deleteRecord(rw, recordType, recordID)
			if err != nil {
				return fmt.Errorf("pebble: error enforcing options: %w", err)
			}
		}
	}

	return nil
}

func getRecord(
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

func getOptions(
	r reader,
	recordType string,
) (*databrokerpb.Options, error) {
	options, err := optionsKeySpace.get(r, recordType)
	if isNotFound(err) {
		options = new(databrokerpb.Options)
	} else if err != nil {
		return nil, fmt.Errorf("pebble: error getting options: %w", err)
	}

	return options, nil
}

func lease(
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

func listChangedRecordsAfter(
	r reader,
	recordType string,
	afterRecordVersion uint64,
) ([]*databrokerpb.Record, error) {
	records := make([]*databrokerpb.Record, 0, batchSize)
	var seq iter.Seq2[*databrokerpb.Record, error]
	if recordType == "" {
		seq = recordChangeKeySpace.iterate(r, afterRecordVersion)
	} else {
		seq = recordChangeIndexByTypeKeySpace.iterate(r, recordType, afterRecordVersion)
	}
	for record, err := range seq {
		if err != nil {
			return nil, fmt.Errorf("pebble: error iterating over record changes by type: %w", err)
		}
		records = append(records, record)
		if len(records) > batchSize {
			break
		}
	}
	return records, nil
}

func listLatestRecords(
	r reader,
	recordType string,
	filter storage.FilterExpression,
) ([]*databrokerpb.Record, error) {
	// this is currently inefficient, we need to implement:
	// (1) iterating over a single record type
	// (2) retrieving a single record by (type, id)
	// (3) retrieving records by CIDR index

	var seq iter.Seq2[*databrokerpb.Record, error]
	if recordType == "" {
		seq = recordKeySpace.iterateAll(r)
	} else {
		seq = recordKeySpace.iterate(r, recordType)
	}

	var records []*databrokerpb.Record
	for record, err := range seq {
		if err != nil {
			return nil, fmt.Errorf("pebble: error iterating over records: %w", err)
		}
		if recordMatches(record, filter) {
			records = append(records, record)
		}
	}
	return records, nil
}

func listTypes(
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

func patchRecord(
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

	return updateRecord(rw, record)
}

func patchRecords(
	rw readerWriter,
	records []*databrokerpb.Record,
	fields *fieldmaskpb.FieldMask,
) (patchedRecords []*databrokerpb.Record, err error) {
	// update records
	recordTypes := set.New[string](len(records))
	patchedRecords = make([]*databrokerpb.Record, 0, len(records))
	for _, record := range records {
		recordTypes.Insert(record.GetType())
		record = proto.CloneOf(record)
		err = patchRecord(rw, record, fields)
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
		err = enforceOptions(rw, recordType)
		if err != nil {
			return nil, fmt.Errorf("pebble: error enforcing options (type=%s): %w",
				recordType, err)
		}
	}

	return patchedRecords, err
}

func putRecords(
	rw readerWriter,
	records []*databrokerpb.Record,
) (err error) {
	// update records
	recordTypes := set.New[string](len(records))
	for i := range records {
		recordTypes.Insert(records[i].GetType())
		records[i] = proto.CloneOf(records[i])
		err = updateRecord(rw, records[i])
		if err != nil {
			return fmt.Errorf("pebble: error updating record (type=%s id=%s): %w",
				records[i].GetType(), records[i].GetId(), err)
		}
	}

	// enforce options
	for recordType := range recordTypes.Items() {
		err = enforceOptions(rw, recordType)
		if err != nil {
			return fmt.Errorf("pebble: error enforcing options (type=%s): %w",
				recordType, err)
		}
	}

	return err
}

func setOptions(
	rw readerWriter,
	recordType string,
	options *databrokerpb.Options,
) error {
	var err error
	// if the options are empty, just delete them since we will return empty options on not found
	if proto.Equal(options, new(databrokerpb.Options)) {
		err = optionsKeySpace.delete(rw, recordType)
	} else {
		err = optionsKeySpace.set(rw, recordType, options)
	}
	if err != nil {
		return fmt.Errorf("pebble: error updating options: %w", err)
	}
	return nil
}

func updateRecord(
	rw readerWriter,
	record *databrokerpb.Record,
) error {
	if record.GetDeletedAt() != nil {
		return deleteRecord(rw, record.GetType(), record.GetId())
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
	}

	latestRecordVersion, err := metadataKeySpace.getLatestRecordVersion(rw)
	if err != nil {
		return fmt.Errorf("pebble: error getting latest record version: %w", err)
	}
	latestRecordVersion++

	record.ModifiedAt = timestamppb.Now()
	record.Version = latestRecordVersion

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

	err = metadataKeySpace.setLatestRecordVersion(rw, latestRecordVersion)
	if err != nil {
		return fmt.Errorf("pebble: error setting latest record version: %w", err)
	}

	return nil
}

func isNotFound(err error) bool {
	return errors.Is(err, pebble.ErrNotFound)
}
