// Package inmemory contains an in-memory implementation of the databroker backend.
package inmemory

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/btree"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

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
	cfg      *config
	onChange *signal.Signal

	lastVersion uint64
	closeOnce   sync.Once
	closed      chan struct{}

	mu       sync.RWMutex
	lookup   map[string]*RecordCollection
	capacity map[string]*uint64
	changes  *btree.BTree
}

// New creates a new in-memory backend storage.
func New(options ...Option) *Backend {
	cfg := getConfig(options...)
	backend := &Backend{
		cfg:      cfg,
		onChange: signal.New(),
		closed:   make(chan struct{}),
		lookup:   make(map[string]*RecordCollection),
		capacity: map[string]*uint64{},
		changes:  btree.New(cfg.degree),
	}
	if cfg.expiry != 0 {
		go func() {
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-backend.closed:
					return
				case <-ticker.C:
				}

				backend.removeChangesBefore(time.Now().Add(-cfg.expiry))
			}
		}()
	}
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
	backend.closeOnce.Do(func() {
		close(backend.closed)

		backend.mu.Lock()
		defer backend.mu.Unlock()

		backend.lookup = map[string]*RecordCollection{}
		backend.capacity = map[string]*uint64{}
		backend.changes = btree.New(backend.cfg.degree)
	})
	return nil
}

// Get gets a record from the in-memory store.
func (backend *Backend) Get(_ context.Context, recordType, id string) (*databroker.Record, error) {
	backend.mu.RLock()
	defer backend.mu.RUnlock()

	records := backend.lookup[recordType]
	if records == nil {
		return nil, storage.ErrNotFound
	}

	record := records.Get(id)
	if record == nil {
		return nil, storage.ErrNotFound
	}

	return dup(record), nil
}

// GetAll gets all the records from the in-memory store.
func (backend *Backend) GetAll(_ context.Context) ([]*databroker.Record, uint64, error) {
	backend.mu.RLock()
	defer backend.mu.RUnlock()

	var all []*databroker.Record
	for _, rs := range backend.lookup {
		for _, r := range rs.List() {
			all = append(all, dup(r))
		}
	}
	return all, backend.lastVersion, nil
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

// Put puts a record into the in-memory store.
func (backend *Backend) Put(_ context.Context, record *databroker.Record) error {
	if record == nil {
		return fmt.Errorf("records cannot be nil")
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()
	defer backend.onChange.Broadcast()

	backend.recordChange(record)

	c, ok := backend.lookup[record.GetType()]
	if !ok {
		c = NewRecordCollection()
		backend.lookup[record.GetType()] = c
	}

	if record.GetDeletedAt() != nil {
		c.Delete(record.GetId())
	} else {
		c.Put(dup(record))
	}

	backend.enforceCapacity(record.GetType())

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

// Sync returns a record stream for any changes after version.
func (backend *Backend) Sync(ctx context.Context, version uint64) (storage.RecordStream, error) {
	return newRecordStream(ctx, backend, version), nil
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

	if collection.Len() <= int(capacity) {
		return
	}

	records := collection.List()
	for len(records) > int(capacity) {
		// delete the record
		record := dup(records[0])
		record.DeletedAt = timestamppb.Now()
		backend.recordChange(record)
		collection.Delete(record.GetId())

		// move forward
		records = records[1:]
	}
}

func (backend *Backend) getSince(version uint64) []*databroker.Record {
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
	return records
}

func (backend *Backend) nextVersion() uint64 {
	return atomic.AddUint64(&backend.lastVersion, 1)
}

func dup(record *databroker.Record) *databroker.Record {
	return proto.Clone(record).(*databroker.Record)
}
