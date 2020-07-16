// Package redis is the redis database, implements storage.Backend interface.
package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/gomodule/redigo/redis"
	"google.golang.org/protobuf/types/known/anypb"

	internal_databroker "github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

var _ storage.Backend = (*DB)(nil)

// DB wraps redis conn to interact with redis server.
type DB struct {
	pool                   *redis.Pool
	deletePermanentlyAfter int64
	recordType             string
	lastVersion            uint64
}

// New returns new DB instance.
func New(address string) (*DB, error) {
	db := &DB{
		pool: &redis.Pool{
			Wait: true,
			DialContext: func(ctx context.Context) (redis.Conn, error) {
				ctx, cancelFn := context.WithTimeout(ctx, 5*time.Second)
				defer cancelFn()
				c, err := redis.DialContext(ctx, "tcp", address)
				if err != nil {
					return nil, fmt.Errorf(`redis.DialURL(): %w`, err)
				}
				return c, nil
			},
			TestOnBorrow: func(c redis.Conn, t time.Time) error {
				if time.Since(t) < time.Minute {
					return nil
				}
				_, err := c.Do("PING")
				if err != nil {
					return fmt.Errorf(`c.Do("PING"): %w`, err)
				}
				return nil
			},
		},
		deletePermanentlyAfter: int64(internal_databroker.DefaultDeletePermanentlyAfter.Seconds()),
	}
	return db, nil
}

// Put sets new record for given id with input data.
func (db *DB) Put(ctx context.Context, id string, data *anypb.Any) error {
	c := db.pool.Get()
	defer c.Close()
	record := db.Get(ctx, id)
	if record == nil {
		record = new(databroker.Record)
		record.CreatedAt = ptypes.TimestampNow()
	}

	record.Data = data
	record.ModifiedAt = ptypes.TimestampNow()
	record.Type = db.recordType
	record.Id = id
	record.Version = fmt.Sprintf("%012X", atomic.AddUint64(&db.lastVersion, 1))
	b, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if _, err := c.Do("SET", id, string(b)); err != nil {
		return err
	}
	return nil
}

// Get retrieves a record from redis.
func (db *DB) Get(_ context.Context, id string) *databroker.Record {
	c := db.pool.Get()
	defer c.Close()

	b, err := redis.Bytes(c.Do("GET", id))
	if err != nil {
		return nil
	}

	record := &databroker.Record{}
	err = json.Unmarshal(b, record)
	if err != nil {
		return nil
	}
	return record
}

// GetAll retrieves all records from redis.
func (db *DB) GetAll(ctx context.Context) []*databroker.Record {
	return db.getAll(ctx, func(record *databroker.Record) bool { return true })
}

// List retrieves all records since given version.
func (db *DB) List(ctx context.Context, sinceVersion string) []*databroker.Record {
	return db.getAll(ctx, func(record *databroker.Record) bool {
		return record.Version > sinceVersion
	})
}

// Delete sets a record DeletedAt field and set its TTL.
func (db *DB) Delete(ctx context.Context, id string) error {
	c := db.pool.Get()
	defer c.Close()

	r := db.Get(ctx, id)
	if r == nil {
		return errors.New("not found")
	}
	r.DeletedAt = ptypes.TimestampNow()
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err := c.Do("SET", id, string(b), "EX", db.deletePermanentlyAfter); err != nil {
		return err
	}
	return nil
}

// ClearDeleted is a no-op, it exists for satisfying storage.Backend interface only.
// Delete methods already set the record TTL, so record will be deleted from redis after TTL.
func (db *DB) ClearDeleted(_ context.Context, _ time.Time) {}

func (db *DB) getAll(_ context.Context, filter func(record *databroker.Record) bool) []*databroker.Record {
	c := db.pool.Get()
	defer c.Close()
	iter := 0
	records := make([]*databroker.Record, 0)
	for {
		arr, err := redis.Values(c.Do("SCAN", iter, "MATCH", "*"))
		if err != nil {
			return nil
		}

		iter, _ = redis.Int(arr[0], nil)
		ids, _ := redis.Strings(arr[1], nil)

		for _, id := range ids {
			b, err := redis.Bytes(c.Do("GET", id))
			if err != nil {
				return nil
			}

			record := &databroker.Record{}
			if err := json.Unmarshal(b, record); err != nil {
				return nil
			}
			if filter(record) {
				records = append(records, record)
			}
		}

		if iter == 0 {
			break
		}
	}

	return records
}
