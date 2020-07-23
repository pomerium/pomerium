// Package redis is the redis database, implements storage.Backend interface.
package redis

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/gomodule/redigo/redis"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

// Name is the storage type name for redis backend.
const Name = "redis"

var _ storage.Backend = (*DB)(nil)

// DB wraps redis conn to interact with redis server.
type DB struct {
	pool                   *redis.Pool
	deletePermanentlyAfter int64
	recordType             string
	lastVersion            uint64
	versionSet             string
	deletedSet             string
}

// New returns new DB instance.
func New(address, recordType string, deletePermanentAfter int64) (*DB, error) {
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
		deletePermanentlyAfter: deletePermanentAfter,
		recordType:             recordType,
		versionSet:             "version_set",
		deletedSet:             "deleted_set",
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
	b, err := proto.Marshal(record)
	if err != nil {
		return err
	}
	cmds := []map[string][]interface{}{
		{"MULTI": nil},
		{"HSET": {db.recordType, id, string(b)}},
		{"ZADD": {db.versionSet, db.lastVersion, id}},
	}
	if err := db.tx(c, cmds); err != nil {
		return err
	}
	return nil
}

// Get retrieves a record from redis.
func (db *DB) Get(_ context.Context, id string) *databroker.Record {
	c := db.pool.Get()
	defer c.Close()

	b, err := redis.Bytes(c.Do("HGET", db.recordType, id))
	if err != nil {
		return nil
	}

	return db.toPbRecord(b)
}

// GetAll retrieves all records from redis.
func (db *DB) GetAll(ctx context.Context) []*databroker.Record {
	return db.getAll(ctx, func(record *databroker.Record) bool { return true })
}

// List retrieves all records since given version.
//
// "version" is in hex format, invalid version will be treated as 0.
func (db *DB) List(ctx context.Context, sinceVersion string) []*databroker.Record {
	c := db.pool.Get()
	defer c.Close()

	v, err := strconv.ParseUint(sinceVersion, 16, 64)
	if err != nil {
		v = 0
	}

	ids, err := redis.Strings(c.Do("ZRANGEBYSCORE", db.versionSet, fmt.Sprintf("(%d", v), "+inf"))
	if err != nil {
		return nil
	}

	records := make([]*databroker.Record, 0, len(ids))
	for _, id := range ids {
		b, err := redis.Bytes(c.Do("HGET", db.recordType, id))
		if err != nil {
			continue
		}
		records = append(records, db.toPbRecord(b))
	}
	return records
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
	r.Version = fmt.Sprintf("%012X", atomic.AddUint64(&db.lastVersion, 1))
	b, err := proto.Marshal(r)
	if err != nil {
		return err
	}
	cmds := []map[string][]interface{}{
		{"MULTI": nil},
		{"HSET": {db.recordType, id, string(b)}},
		{"SADD": {db.deletedSet, id}},
		{"ZADD": {db.versionSet, db.lastVersion, id}},
	}
	if err := db.tx(c, cmds); err != nil {
		return err
	}
	return nil
}

// ClearDeleted clears all the currently deleted records older than the given cutoff.
func (db *DB) ClearDeleted(_ context.Context, cutoff time.Time) {
	c := db.pool.Get()
	defer c.Close()

	ids, _ := redis.Strings(c.Do("SMEMBERS", db.deletedSet))
	for _, id := range ids {
		b, _ := redis.Bytes(c.Do("HGET", db.recordType, id))
		record := db.toPbRecord(b)
		if record == nil {
			continue
		}

		ts, _ := ptypes.Timestamp(record.DeletedAt)
		if ts.Before(cutoff) {
			cmds := []map[string][]interface{}{
				{"MULTI": nil},
				{"HDEL": {db.recordType, id}},
				{"ZREM": {db.versionSet, id}},
				{"SREM": {db.deletedSet, id}},
			}
			_ = db.tx(c, cmds)
		}
	}
}

func (db *DB) getAll(_ context.Context, filter func(record *databroker.Record) bool) []*databroker.Record {
	c := db.pool.Get()
	defer c.Close()
	iter := 0
	records := make([]*databroker.Record, 0)
	for {
		arr, err := redis.Values(c.Do("HSCAN", db.recordType, iter, "MATCH", "*"))
		if err != nil {
			return nil
		}

		iter, _ = redis.Int(arr[0], nil)
		pairs, _ := redis.StringMap(arr[1], nil)

		for _, v := range pairs {
			record := db.toPbRecord([]byte(v))
			if record == nil {
				continue
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

func (db *DB) toPbRecord(b []byte) *databroker.Record {
	record := &databroker.Record{}
	if err := proto.Unmarshal(b, record); err != nil {
		return nil
	}
	return record
}

func (db *DB) tx(c redis.Conn, commands []map[string][]interface{}) error {
	for _, m := range commands {
		for cmd, args := range m {
			if err := c.Send(cmd, args...); err != nil {
				return err
			}
		}
	}

	_, err := c.Do("EXEC")
	return err
}
