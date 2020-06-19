package memory

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/btree"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/internal/grpc/databroker"
)

type byIDRecord struct {
	*databroker.Record
}

func (k byIDRecord) Less(than btree.Item) bool {
	return k.Id < than.(byIDRecord).Id
}

type byVersionRecord struct {
	*databroker.Record
}

func (k byVersionRecord) Less(than btree.Item) bool {
	return k.Version < than.(byVersionRecord).Version
}

// DB is an in-memory database of records using b-trees.
type DB struct {
	recordType string

	lastVersion uint64

	mu         sync.Mutex
	byID       *btree.BTree
	byVersion  *btree.BTree
	deletedIDs []string
}

// NewDB creates a new in-memory database for the given record type.
func NewDB(recordType string, btreeDegree int) *DB {
	return &DB{
		recordType: recordType,
		byID:       btree.New(btreeDegree),
		byVersion:  btree.New(btreeDegree),
	}
}

// ClearDeleted clears all the currently deleted records older than the given cutoff.
func (db *DB) ClearDeleted(cutoff time.Time) {
	db.mu.Lock()
	defer db.mu.Unlock()

	var remaining []string
	for _, id := range db.deletedIDs {
		record, _ := db.byID.Get(byIDRecord{Record: &databroker.Record{Id: id}}).(byIDRecord)
		ts, _ := ptypes.Timestamp(record.DeletedAt)
		if ts.Before(cutoff) {
			db.byID.Delete(record)
			db.byVersion.Delete(byVersionRecord(record))
		} else {
			remaining = append(remaining, id)
		}
	}
	db.deletedIDs = remaining
}

// Delete marks a record as deleted.
func (db *DB) Delete(id string) {
	db.replaceOrInsert(id, func(record *databroker.Record) {
		record.DeletedAt = ptypes.TimestampNow()
		db.deletedIDs = append(db.deletedIDs, id)
	})
}

// Get gets a record from the db.
func (db *DB) Get(id string) *databroker.Record {
	record, ok := db.byID.Get(byIDRecord{Record: &databroker.Record{Id: id}}).(byIDRecord)
	if !ok {
		return nil
	}
	return record.Record
}

// GetAll gets all the records in the db.
func (db *DB) GetAll() []*databroker.Record {
	var records []*databroker.Record
	db.byID.Ascend(func(item btree.Item) bool {
		records = append(records, item.(byIDRecord).Record)
		return true
	})
	return records
}

// List lists all the changes since the given version.
func (db *DB) List(sinceVersion string) []*databroker.Record {
	var records []*databroker.Record
	db.byVersion.AscendGreaterOrEqual(byVersionRecord{Record: &databroker.Record{Version: sinceVersion}}, func(i btree.Item) bool {
		record := i.(byVersionRecord)
		if record.Version > sinceVersion {
			records = append(records, record.Record)
		}
		return true
	})
	return records
}

// Set replaces or inserts a record in the db.
func (db *DB) Set(id string, data *anypb.Any) {
	db.replaceOrInsert(id, func(record *databroker.Record) {
		record.Data = data
	})
}

func (db *DB) replaceOrInsert(id string, f func(record *databroker.Record)) {
	db.mu.Lock()
	defer db.mu.Unlock()

	record, ok := db.byID.Get(byIDRecord{Record: &databroker.Record{Id: id}}).(byIDRecord)
	if ok {
		db.byVersion.Delete(byVersionRecord(record))
		record.Record = proto.Clone(record.Record).(*databroker.Record)
	} else {
		record.Record = new(databroker.Record)
	}
	f(record.Record)
	if record.CreatedAt == nil {
		record.CreatedAt = ptypes.TimestampNow()
	}
	record.ModifiedAt = ptypes.TimestampNow()
	record.Type = db.recordType
	record.Id = id
	record.Version = fmt.Sprintf("%012X", atomic.AddUint64(&db.lastVersion, 1))
	db.byID.ReplaceOrInsert(record)
	db.byVersion.ReplaceOrInsert(byVersionRecord(record))
}
