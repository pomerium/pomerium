// Package inmemory contains an in-memory implementation of the databroker backend.
package inmemory

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/btree"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/storage"
)

type lease struct {
	id     string
	expiry time.Time
}

type recordChange struct {
	record *databroker.Record
}

func (change recordChange) Less(item btree.Item) bool {
	that, ok := item.(recordChange)
	if !ok {
		return false
	}

	return change.record.GetVersion() < that.record.GetVersion()
}

// A Backend stores data in-memory.
type Backend struct {
	cfg            *config
	onRecordChange *signal.Signal
	serverVersion  uint64

	lastVersion uint64
	closeCtx    context.Context
	close       context.CancelFunc

	mu       sync.RWMutex
	lookup   map[string]storage.RecordCollection
	capacity map[string]*uint64
	changes  *btree.BTree
	leases   map[string]*lease
}

// New creates a new in-memory backend storage.
func New(options ...Option) *Backend {
	cfg := getConfig(options...)
	backend := &Backend{
		cfg:            cfg,
		onRecordChange: signal.New(),
		serverVersion:  cryptutil.NewRandomUInt64(),
		lookup:         make(map[string]storage.RecordCollection),
		capacity:       map[string]*uint64{},
		changes:        btree.New(cfg.degree),
		leases:         make(map[string]*lease),
	}
	backend.closeCtx, backend.close = context.WithCancel(context.Background())
	if cfg.expiry != 0 {
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-backend.closeCtx.Done():
					return
				case <-ticker.C:
				}

				backend.removeChangesBefore(time.Now().Add(-cfg.expiry))
			}
		}()
	}

	health.ReportOK(health.StorageBackend, health.StrAttr("backend", "in-memory"))

	return backend
}

func (backend *Backend) removeChangesBefore(cutoff time.Time) {
	backend.mu.Lock()
	defer backend.mu.Unlock()

	for {
		item := backend.changes.Min()
		if item == nil {
			break
		}
		change, ok := item.(recordChange)
		if !ok {
			panic(fmt.Sprintf("invalid type in changes btree: %T", item))
		}
		if change.record.GetModifiedAt().AsTime().Before(cutoff) {
			_ = backend.changes.DeleteMin()
			continue
		}

		// nothing left to remove
		break
	}
}

// Close closes the in-memory store and erases any stored data.
func (backend *Backend) Close() error {
	backend.close()
	return nil
}

// Get gets a record from the in-memory store.
func (backend *Backend) Get(_ context.Context, recordType, id string) (*databroker.Record, error) {
	backend.mu.RLock()
	defer backend.mu.RUnlock()
	if record := backend.get(recordType, id); record != nil {
		return record, nil
	}
	return nil, storage.ErrNotFound
}

// get gets a record from the in-memory store, assuming the RWMutex is held.
func (backend *Backend) get(recordType, id string) *databroker.Record {
	records := backend.lookup[recordType]
	if records == nil {
		return nil
	}

	record, ok := records.Get(id)
	if !ok {
		return nil
	}

	return dup(record)
}

// GetOptions returns the options for a type in the in-memory store.
func (backend *Backend) GetOptions(_ context.Context, recordType string) (*databroker.Options, error) {
	backend.mu.RLock()
	defer backend.mu.RUnlock()

	options := new(databroker.Options)
	if capacity := backend.capacity[recordType]; capacity != nil {
		options.Capacity = proto.Uint64(*capacity)
	}

	return options, nil
}

// Lease acquires or renews a lease.
func (backend *Backend) Lease(_ context.Context, leaseName, leaseID string, ttl time.Duration) (bool, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()

	l, ok := backend.leases[leaseName]
	// if there is no lease, or its expired, acquire a new one.
	if !ok || l.expiry.Before(time.Now()) {
		backend.leases[leaseName] = &lease{
			id:     leaseID,
			expiry: time.Now().Add(ttl),
		}
		return true, nil
	}

	// if the lease doesn't match, we can't acquire it
	if l.id != leaseID {
		return false, nil
	}

	// release the lease
	if ttl <= 0 {
		delete(backend.leases, leaseName)
		return false, nil
	}

	// update the expiry (renew the lease)
	l.expiry = time.Now().Add(ttl)
	return true, nil
}

// ListTypes lists the record types.
func (backend *Backend) ListTypes(_ context.Context) ([]string, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	keys := slices.Sorted(maps.Keys(backend.lookup))

	return keys, nil
}

// Put puts a record into the in-memory store.
func (backend *Backend) Put(ctx context.Context, records []*databroker.Record) (serverVersion uint64, err error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	defer backend.onRecordChange.Broadcast(ctx)

	recordTypes := map[string]struct{}{}
	for _, record := range records {
		if record == nil {
			return backend.serverVersion, fmt.Errorf("records cannot be nil")
		}

		ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
			return c.Str("db-op", "put").
				Str("db-id", record.Id).
				Str("db-type", record.Type)
		})

		backend.update(record)

		recordTypes[record.GetType()] = struct{}{}
	}
	for recordType := range recordTypes {
		backend.enforceCapacity(recordType)
	}

	return backend.serverVersion, nil
}

// update stores a record into the in-memory store, assuming the RWMutex is held.
func (backend *Backend) update(record *databroker.Record) {
	backend.recordChange(record)

	c, ok := backend.lookup[record.GetType()]
	if !ok {
		c = storage.NewRecordCollection()
		backend.lookup[record.GetType()] = c
	}

	c.Put(record)
}

// Patch updates the specified fields of existing record(s).
func (backend *Backend) Patch(
	ctx context.Context, records []*databroker.Record, fields *fieldmaskpb.FieldMask,
) (serverVersion uint64, patchedRecords []*databroker.Record, err error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	defer backend.onRecordChange.Broadcast(ctx)

	serverVersion = backend.serverVersion
	patchedRecords = make([]*databroker.Record, 0, len(records))

	for _, record := range records {
		err = backend.patch(record, fields)
		if storage.IsNotFound(err) {
			// Skip any record that does not currently exist.
			continue
		} else if err != nil {
			return serverVersion, patchedRecords, err
		}
		patchedRecords = append(patchedRecords, record)
	}

	return serverVersion, patchedRecords, nil
}

// patch updates the specified fields of an existing record, assuming the RWMutex is held.
func (backend *Backend) patch(record *databroker.Record, fields *fieldmaskpb.FieldMask) error {
	if record == nil {
		return fmt.Errorf("cannot patch using a nil record")
	}

	existing := backend.get(record.GetType(), record.GetId())
	if existing == nil {
		return storage.ErrNotFound
	}

	if err := storage.PatchRecord(existing, record, fields); err != nil {
		return err
	}

	backend.update(record)

	return nil
}

// SetOptions sets the options for a type in the in-memory store.
func (backend *Backend) SetOptions(_ context.Context, recordType string, options *databroker.Options) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()

	if options.Capacity == nil {
		delete(backend.capacity, recordType)
	} else {
		backend.capacity[recordType] = proto.Uint64(options.GetCapacity())
		backend.enforceCapacity(recordType)
	}

	return nil
}

// Sync returns a record stream for any changes after recordVersion.
func (backend *Backend) Sync(ctx context.Context, recordType string, serverVersion, recordVersion uint64, wait bool) storage.RecordIterator {
	return backend.iterateChangedRecords(ctx, recordType, serverVersion, recordVersion, wait)
}

// SyncLatest returns a record iterator for all the records.
func (backend *Backend) SyncLatest(
	ctx context.Context,
	recordType string,
	expr storage.FilterExpression,
) (serverVersion, recordVersion uint64, seq storage.RecordIterator, err error) {
	backend.mu.RLock()
	serverVersion = backend.serverVersion
	recordVersion = backend.lastVersion
	backend.mu.RUnlock()
	return serverVersion, recordVersion, backend.iterateLatestRecords(ctx, recordType, expr), nil
}

func (backend *Backend) recordChange(record *databroker.Record) {
	record.ModifiedAt = timestamppb.Now()
	record.Version = backend.nextVersion()
	backend.changes.ReplaceOrInsert(recordChange{record: dup(record)})
}

func (backend *Backend) enforceCapacity(recordType string) {
	collection, ok := backend.lookup[recordType]
	if !ok {
		return
	}

	ptr := backend.capacity[recordType]
	if ptr == nil {
		return
	}
	capacity := *ptr

	for collection.Len() > int(capacity) {
		r, ok := collection.Oldest()
		if !ok {
			break
		}
		r.DeletedAt = timestamppb.Now()
		backend.recordChange(r)
		collection.Put(r)
	}
}

func (backend *Backend) listChangedRecordsAfter(recordType string, version uint64) []*databroker.Record {
	backend.mu.RLock()
	defer backend.mu.RUnlock()

	var records []*databroker.Record
	pivot := recordChange{record: &databroker.Record{Version: version}}
	backend.changes.AscendGreaterOrEqual(pivot, func(item btree.Item) bool {
		change, ok := item.(recordChange)
		if !ok {
			panic(fmt.Sprintf("invalid type in changes btree: %T", item))
		}
		record := change.record
		// skip the pivoting version as we only want records after it
		if record.GetVersion() != version {
			records = append(records, dup(record))
		}
		return true
	})

	if recordType != "" {
		var filtered []*databroker.Record
		for _, record := range records {
			if record.GetType() == recordType {
				filtered = append(filtered, record)
			}
		}
		records = filtered
	}
	return records
}

func (backend *Backend) nextVersion() uint64 {
	return atomic.AddUint64(&backend.lastVersion, 1)
}

func dup(record *databroker.Record) *databroker.Record {
	return proto.Clone(record).(*databroker.Record)
}
