// Package redis is the redis database, implements storage.Backend interface.
package redis

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/gomodule/redigo/redis"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

// Name is the storage type name for redis backend.
const Name = "redis"
const watchAction = "zadd"

var _ storage.Backend = (*DB)(nil)

// DB wraps redis conn to interact with redis server.
type DB struct {
	pool                   *redis.Pool
	deletePermanentlyAfter int64
	recordType             string
	lastVersionKey         string
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
		versionSet:             recordType + "_version_set",
		deletedSet:             recordType + "_deleted_set",
		lastVersionKey:         recordType + "_last_version",
	}
	return db, nil
}

// Put sets new record for given id with input data.
func (db *DB) Put(ctx context.Context, id string, data *anypb.Any) error {
	c := db.pool.Get()
	defer c.Close()
	record, err := db.Get(ctx, id)
	if err != nil {
		record = new(databroker.Record)
		record.CreatedAt = ptypes.TimestampNow()
	}

	lastVersion, err := redis.Int64(c.Do("INCR", db.lastVersionKey))
	if err != nil {
		return err
	}
	record.Data = data
	record.ModifiedAt = ptypes.TimestampNow()
	record.Type = db.recordType
	record.Id = id
	record.Version = fmt.Sprintf("%012X", lastVersion)
	b, err := proto.Marshal(record)
	if err != nil {
		return err
	}
	cmds := []map[string][]interface{}{
		{"MULTI": nil},
		{"HSET": {db.recordType, id, string(b)}},
		{"ZADD": {db.versionSet, lastVersion, id}},
	}
	if err := db.tx(c, cmds); err != nil {
		return err
	}
	return nil
}

// Get retrieves a record from redis.
func (db *DB) Get(_ context.Context, id string) (*databroker.Record, error) {
	c := db.pool.Get()
	defer c.Close()

	b, err := redis.Bytes(c.Do("HGET", db.recordType, id))
	if err != nil {
		return nil, err
	}

	return db.toPbRecord(b)
}

// GetAll retrieves all records from redis.
func (db *DB) GetAll(ctx context.Context) ([]*databroker.Record, error) {
	return db.getAll(ctx, func(record *databroker.Record) bool { return true })
}

// List retrieves all records since given version.
//
// "version" is in hex format, invalid version will be treated as 0.
func (db *DB) List(ctx context.Context, sinceVersion string) ([]*databroker.Record, error) {
	c := db.pool.Get()
	defer c.Close()

	v, err := strconv.ParseUint(sinceVersion, 16, 64)
	if err != nil {
		v = 0
	}

	ids, err := redis.Strings(c.Do("ZRANGEBYSCORE", db.versionSet, fmt.Sprintf("(%d", v), "+inf"))
	if err != nil {
		return nil, err
	}

	pbRecords := make([]*databroker.Record, 0, len(ids))
	for _, id := range ids {
		b, err := redis.Bytes(c.Do("HGET", db.recordType, id))
		if err != nil {
			return nil, err
		}
		pbRecord, err := db.toPbRecord(b)
		if err != nil {
			return nil, err
		}
		pbRecords = append(pbRecords, pbRecord)
	}
	return pbRecords, nil
}

// Delete sets a record DeletedAt field and set its TTL.
func (db *DB) Delete(ctx context.Context, id string) error {
	c := db.pool.Get()
	defer c.Close()

	r, err := db.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get record: %w", err)
	}

	lastVersion, err := redis.Int64(c.Do("INCR", db.lastVersionKey))
	if err != nil {
		return err
	}

	r.DeletedAt = ptypes.TimestampNow()
	r.Version = fmt.Sprintf("%012X", lastVersion)
	b, err := proto.Marshal(r)
	if err != nil {
		return err
	}
	cmds := []map[string][]interface{}{
		{"MULTI": nil},
		{"HSET": {db.recordType, id, string(b)}},
		{"SADD": {db.deletedSet, id}},
		{"ZADD": {db.versionSet, lastVersion, id}},
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
		record, err := db.toPbRecord(b)
		if err != nil {
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

func doNotify(ctx context.Context, psc *redis.PubSubConn, ch chan struct{}) error {
	switch v := psc.ReceiveWithTimeout(time.Second).(type) {
	case redis.Message:
		log.Debug().Str("action", string(v.Data)).Msg("Got redis message")
		if string(v.Data) != watchAction {
			return nil
		}
		select {
		case <-ctx.Done():
			log.Warn().Err(ctx.Err()).Msg("unable to notify channel")
			return ctx.Err()
		case ch <- struct{}{}:
		}
	case error:
		log.Debug().Err(v).Msg("redis subscribe error")
		return v
	}
	return nil
}

// Watch returns a channel to the caller, when there is a change to the version set,
// sending message to the channel to notify the caller.
func (db *DB) Watch(ctx context.Context) chan struct{} {
	ch := make(chan struct{})
	go func() {
		c := db.pool.Get()
		defer func() {
			close(ch)
		}()

		// Setup notifications, we only care about changes to db.version_set.
		if _, err := c.Do("CONFIG", "SET", "notify-keyspace-events", "Kz"); err != nil {
			log.Error().Err(err).Msg("failed to setup redis notification")
			c.Close()
			return
		}

		c.Close()
		eb := backoff.NewExponentialBackOff()

	top:
		psConn := db.pool.Get()
		defer psConn.Close()
		psc := redis.PubSubConn{Conn: psConn}
		defer psc.Conn.Close()
		if err := psc.PSubscribe("__keyspace*__:" + db.versionSet); err != nil {
			log.Error().Err(err).Msg("failed to subscribe to version set channel")
			return
		}

		for {
			select {
			case <-ctx.Done():
				log.Error().Err(ctx.Err()).Msg("stop subscribing to version set channel")
				return
			default:
				err := doNotify(ctx, &psc, ch)
				if err == nil {
					continue
				}
				if err, ok := err.(net.Error); ok && err.Timeout() {
					select {
					case <-ctx.Done():
						return
					case <-time.After(eb.NextBackOff()):
					}
					goto top
				}
				log.Error().Err(ctx.Err()).Msg("failed to notify channel")
				return
			}
		}
	}()

	return ch
}

func (db *DB) getAll(_ context.Context, filter func(record *databroker.Record) bool) ([]*databroker.Record, error) {
	c := db.pool.Get()
	defer c.Close()
	iter := 0
	records := make([]*databroker.Record, 0)
	for {
		arr, err := redis.Values(c.Do("HSCAN", db.recordType, iter, "MATCH", "*"))
		if err != nil {
			return nil, err
		}

		iter, _ = redis.Int(arr[0], nil)
		pairs, _ := redis.StringMap(arr[1], nil)

		for _, v := range pairs {
			record, err := db.toPbRecord([]byte(v))
			if err != nil {
				return nil, err
			}
			if filter(record) {
				records = append(records, record)
			}
		}

		if iter == 0 {
			break
		}
	}

	return records, nil
}

func (db *DB) toPbRecord(b []byte) (*databroker.Record, error) {
	record := &databroker.Record{}
	if err := proto.Unmarshal(b, record); err != nil {
		return nil, err
	}
	return record, nil
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
