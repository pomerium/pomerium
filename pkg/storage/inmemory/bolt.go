package inmemory

import (
	"fmt"

	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func (backend *Backend) openAndLoad() error {
	if err := backend.open(); err != nil {
		return fmt.Errorf("failed to open bolt database: %w", err)
	}
	if err := backend.load(); err != nil {
		return fmt.Errorf("failed to load data: %w", err)
	}
	return nil
}

func (backend *Backend) open() error {
	db, err := bbolt.Open(backend.cfg.file, 0o600, nil)
	if err != nil {
		return err
	}
	backend.db = db
	return nil
}

func (backend *Backend) load() error {
	return backend.db.View(func(tx *bbolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bbolt.Bucket) error {
			return backend.loadBucket(name, b)
		})
	})
}

func (backend *Backend) loadBucket(bucketName []byte, bucket *bbolt.Bucket) error {
	return bucket.ForEach(func(k, v []byte) error {
		typeName := string(bucketName)
		c, ok := backend.lookup[typeName]
		if !ok {
			c = NewRecordCollection()
			backend.lookup[typeName] = c
		}

		return backend.loadRecord(c, k, v)
	})
}

func (backend *Backend) loadRecord(dst *RecordCollection, key, data []byte) error {
	record := new(databroker.Record)
	if err := proto.Unmarshal(data, record); err != nil {
		return fmt.Errorf("failed to unmarshal record: %w", err)
	}

	if record.GetId() != string(key) {
		return fmt.Errorf("record id does not match key: %s != %s", record.GetId(), key)
	}

	dst.Put(record)
	return nil
}

func (backend *Backend) delete(record *databroker.Record) error {
	return backend.db.Update(func(tx *bbolt.Tx) error {
		return backend.deleteRecord(tx, record)
	})
}

func (backend *Backend) deleteRecord(tx *bbolt.Tx, record *databroker.Record) error {
	bucketName := []byte(record.GetType())
	bucket := tx.Bucket(bucketName)
	if bucket == nil {
		return nil
	}

	return bucket.Delete([]byte(record.GetId()))
}

func (backend *Backend) store(record *databroker.Record) error {
	return backend.db.Update(func(tx *bbolt.Tx) error {
		return backend.storeRecord(tx, record)
	})
}

func (backend *Backend) storeRecord(tx *bbolt.Tx, record *databroker.Record) error {
	data, err := proto.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal record: %w", err)
	}

	bucketName := []byte(record.GetType())
	bucket, err := tx.CreateBucketIfNotExists(bucketName)
	if err != nil {
		return fmt.Errorf("failed to create bucket: %w", err)
	}

	return bucket.Put([]byte(record.GetId()), data)
}

func (backend *Backend) close() error {
	return backend.db.Close()
}
