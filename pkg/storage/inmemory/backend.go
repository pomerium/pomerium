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

type recordKey struct {
	Type string
	ID   string
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
	cfg      *config
	onChange *signal.Signal

	lastVersion uint64
	closeOnce   sync.Once
	closed      chan struct{}

	mu      sync.RWMutex
	lookup  map[recordKey]*databroker.Record
	changes *btree.BTree
}

// New creates a new in-memory backend storage.
func New(options ...Option) *Backend {
	cfg := getConfig(options...)
	backend := &Backend{
		cfg:      cfg,
		onChange: signal.New(),
		closed:   make(chan struct{}),
		lookup:   make(map[recordKey]*databroker.Record),
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

		backend.lookup = map[recordKey]*databroker.Record{}
		backend.changes = btree.New(backend.cfg.degree)
	})
	return nil
}

// Get gets a record from the in-memory store.
func (backend *Backend) Get(_ context.Context, recordType, id string) (*databroker.Record, error) {
	backend.mu.RLock()
	defer backend.mu.RUnlock()

	key := recordKey{Type: recordType, ID: id}
	record, ok := backend.lookup[key]
	if !ok {
		return nil, storage.ErrNotFound
	}

	return dup(record), nil
}

// GetAll gets all the records from the in-memory store.
func (backend *Backend) GetAll(_ context.Context) ([]*databroker.Record, uint64, error) {
	backend.mu.RLock()
	defer backend.mu.RUnlock()

	var records []*databroker.Record
	for _, record := range backend.lookup {
		records = append(records, dup(record))
	}
	return records, backend.lastVersion, nil
}

// Put puts a record into the in-memory store.
func (backend *Backend) Put(_ context.Context, record *databroker.Record) error {
	if record == nil {
		return fmt.Errorf("records cannot be nil")
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()
	defer backend.onChange.Broadcast()

	record.ModifiedAt = timestamppb.Now()
	record.Version = backend.nextVersion()
	backend.changes.ReplaceOrInsert(recordChange{record: dup(record)})

	key := recordKey{Type: record.GetType(), ID: record.GetId()}
	if record.GetDeletedAt() != nil {
		delete(backend.lookup, key)
	} else {
		backend.lookup[key] = dup(record)
	}

	return nil
}

// Sync returns a record stream for any changes after version.
func (backend *Backend) Sync(ctx context.Context, version uint64) (storage.RecordStream, error) {
	return newRecordStream(ctx, backend, version), nil
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
