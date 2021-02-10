package inmemory

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/btree"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

var timeNow = time.Now

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

				backend.removeChangesBefore(timeNow().Add(-cfg.expiry))
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
		}
	}
}

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

func (backend *Backend) Get(_ context.Context, recordType, id string) (*databroker.Record, error) {
	backend.mu.RLock()
	defer backend.mu.RUnlock()

	key := recordKey{Type: recordType, ID: id}
	record, ok := backend.lookup[key]
	if !ok {
		return nil, storage.ErrNotFound
	}

	return record, nil
}

func (backend *Backend) GetAll(_ context.Context) ([]*databroker.Record, error) {
	backend.mu.RLock()
	defer backend.mu.RUnlock()

	var records []*databroker.Record
	for _, record := range backend.lookup {
		records = append(records, record)
	}
	return records, nil
}

func (backend *Backend) Put(_ context.Context, record *databroker.Record) error {
	if record == nil {
		return fmt.Errorf("records cannot be nil")
	}

	backend.mu.Lock()
	defer backend.mu.Unlock()
	defer backend.onChange.Broadcast()

	record.ModifiedAt = timestamppb.New(timeNow())
	record.Version = backend.nextVersion()
	backend.changes.ReplaceOrInsert(recordChange{record: record})

	key := recordKey{Type: record.GetType(), ID: record.GetId()}
	if record.GetDeletedAt() != nil {
		delete(backend.lookup, key)
	} else {
		backend.lookup[key] = record
	}

	return nil
}

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
			records = append(records, record)
		}
		return true
	})
	return records
}

func (backend *Backend) nextVersion() uint64 {
	return atomic.AddUint64(&backend.lastVersion, 1)
}
