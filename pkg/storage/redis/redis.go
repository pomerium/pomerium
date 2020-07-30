// Package redis is the redis database, implements storage.Backend interface.
package redis

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/gomodule/redigo/redis"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

// Name is the storage type name for redis backend.
const Name = config.StorageRedisName
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
	tlsConfig              *tls.Config
}

// New returns new DB instance.
func New(rawURL, recordType string, deletePermanentAfter int64, opts ...Option) (*DB, error) {
	db := &DB{
		deletePermanentlyAfter: deletePermanentAfter,
		recordType:             recordType,
		versionSet:             recordType + "_version_set",
		deletedSet:             recordType + "_deleted_set",
		lastVersionKey:         recordType + "_last_version",
	}

	metrics.AddRedisMetrics(db.pool.Stats)
	for _, o := range opts {
		o(db)
	}
	db.pool = &redis.Pool{
		Wait: true,
		Dial: func() (redis.Conn, error) {
			c, err := redis.DialURL(rawURL, redis.DialTLSConfig(db.tlsConfig))
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
	}

	return db, nil
}

// Put sets new record for given id with input data.
func (db *DB) Put(ctx context.Context, id string, data *anypb.Any) (err error) {
	c := db.pool.Get()
	_, span := trace.StartSpan(ctx, "databroker.redis.Put")
	defer span.End()
	defer recordOperation(ctx, time.Now(), "put", err)
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
func (db *DB) Get(ctx context.Context, id string) (rec *databroker.Record, err error) {
	c := db.pool.Get()
	_, span := trace.StartSpan(ctx, "databroker.redis.Get")
	defer span.End()
	defer recordOperation(ctx, time.Now(), "get", err)
	defer c.Close()

	b, err := redis.Bytes(c.Do("HGET", db.recordType, id))
	if err != nil {
		return nil, err
	}

	return db.toPbRecord(b)
}

// GetAll retrieves all records from redis.
func (db *DB) GetAll(ctx context.Context) (recs []*databroker.Record, err error) {
	_, span := trace.StartSpan(ctx, "databroker.redis.GetAll")
	defer span.End()
	defer recordOperation(ctx, time.Now(), "get_all", err)
	return db.getAll(ctx, func(record *databroker.Record) bool { return true })
}

// List retrieves all records since given version.
//
// "version" is in hex format, invalid version will be treated as 0.
func (db *DB) List(ctx context.Context, sinceVersion string) (rec []*databroker.Record, err error) {
	c := db.pool.Get()
	_, span := trace.StartSpan(ctx, "databroker.redis.List")
	defer span.End()
	defer recordOperation(ctx, time.Now(), "list", err)
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
func (db *DB) Delete(ctx context.Context, id string) (err error) {
	c := db.pool.Get()
	_, span := trace.StartSpan(ctx, "databroker.redis.Delete")
	defer span.End()
	defer recordOperation(ctx, time.Now(), "delete", err)
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
func (db *DB) ClearDeleted(ctx context.Context, cutoff time.Time) {
	c := db.pool.Get()
	_, span := trace.StartSpan(ctx, "databroker.redis.ClearDeleted")
	defer span.End()
	var opErr error
	defer recordOperation(ctx, time.Now(), "clear_deleted", opErr)
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
			opErr = db.tx(c, cmds)
		}
	}
}

// doNotifyLoop receives event from redis and send signal to the channel.
func (db *DB) doNotifyLoop(ctx context.Context, ch chan struct{}, psc *redis.PubSubConn) {
	for {
		switch v := psc.Receive().(type) {
		case redis.Message:
			log.Debug().Str("action", string(v.Data)).Msg("got redis message")
			if string(v.Data) != watchAction {
				continue
			}
			select {
			case <-ctx.Done():
				log.Warn().Err(ctx.Err()).Msg("context done, stop receive from redis channel")
				return
			case ch <- struct{}{}:
			}
		case error:
			log.Error().Err(v).Msg("failed to receive from redis channel")
			if _, ok := v.(net.Error); ok {
				return
			}
			if strings.HasPrefix(v.Error(), "redigo: connection closed") {
				return
			}
		}
	}
}

// watch runs the doNotifyLoop. It returns when ctx was done or doNotifyLoop exits.
func (db *DB) watch(ctx context.Context, ch chan struct{}) {
	psConn := db.pool.Get()
	defer psConn.Close()
	psc := redis.PubSubConn{Conn: psConn}
	if err := psc.PSubscribe("__keyspace*__:" + db.versionSet); err != nil {
		log.Error().Err(err).Msg("failed to subscribe to version set channel")
		return
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		db.doNotifyLoop(ctx, ch, &psc)
	}()
	select {
	case <-ctx.Done():
	case <-done:
	}
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
		db.watch(ctx, ch)
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

func recordOperation(ctx context.Context, startTime time.Time, operation string, err error) {
	metrics.RecordStorageOperation(ctx, &metrics.StorageOperationTags{
		Operation: operation,
		Error:     err,
		Backend:   Name,
	}, time.Since(startTime))
}
