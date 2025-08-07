package file

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"iter"
	"net/url"
	"slices"
	"time"

	"github.com/cockroachdb/pebble/v2"

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

		backend.earliestRecordVersion, err = recordChangeKeySpace.getFirstVersion(backend.db)
		if err != nil {
			backend.initErr = fmt.Errorf("pebble: error getting earliest record version: %w", err)
			return
		}

		backend.latestRecordVersion, err = recordChangeKeySpace.getLastVersion(backend.db)
		if err != nil {
			backend.initErr = fmt.Errorf("pebble: error getting earliest record version: %w", err)
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

	backend.options = make(map[string]*databrokerpb.Options)
	for node, err := range optionsKeySpace.iterate(backend.db) {
		if err != nil {
			return fmt.Errorf("pebble: error iterating over options: %w", err)
		}
		backend.options[node.recordType] = node.options
	}

	backend.recordCIDRIndex = newRecordCIDRIndex()
	for record, err := range recordKeySpace.iterateAll(backend.db) {
		if err != nil {
			return fmt.Errorf("pebble: error iterating over records: %w", err)
		}

		if prefix := storage.GetRecordIndexCIDR(record.GetData()); prefix != nil {
			backend.recordCIDRIndex.add(recordCIDRNode{recordType: record.GetType(), recordID: record.GetId(), prefix: *prefix})
		}
	}

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

func compareRecords(a, b *databrokerpb.Record) int {
	return cmp.Or(
		cmp.Compare(a.GetType(), b.GetType()),
		cmp.Compare(a.GetId(), b.GetId()),
	)
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

func isNotFound(err error) bool {
	return errors.Is(err, pebble.ErrNotFound)
}
