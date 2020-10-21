// Package redis is the redis database, implements storage.Backend interface.
package redis

import (
	"context"
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/gomodule/redigo/redis"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

// Name is the storage type name for redis backend.
const Name = config.StorageRedisName

var _ storage.Backend = (*DB)(nil)

// DB wraps redis conn to interact with redis server.
type DB struct {
	recordType            string
	lastVersionKey        string
	lastVersionChannelKey string
	versionSet            string
	deletedSet            string
	rawURL                string
	tlsConfig             *tls.Config

	pool          *redis.Pool
	pubSubTracker *pubSubTracker

	closeOnce sync.Once
	closed    chan struct{}
}

// New returns new DB instance.
func New(rawURL, recordType string, opts ...Option) (*DB, error) {
	db := &DB{
		recordType:            recordType,
		versionSet:            recordType + "_version_set",
		deletedSet:            recordType + "_deleted_set",
		lastVersionKey:        recordType + "_last_version",
		lastVersionChannelKey: recordType + "_last_version_ch",
		rawURL:                rawURL,
		closed:                make(chan struct{}),
	}

	for _, o := range opts {
		o(db)
	}
	db.pool = &redis.Pool{
		Wait: true,
		Dial: func() (redis.Conn, error) {
			return db.dial(context.Background())
		},
		DialContext: db.dial,
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
	db.pubSubTracker = newPubSubTracker(db)
	metrics.AddRedisMetrics(db.pool.Stats)
	return db, nil
}

// Close closes the redis db connection.
func (db *DB) Close() error {
	db.closeOnce.Do(func() {
		close(db.closed)
	})
	return nil
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
		{"PUBLISH": {db.lastVersionChannelKey, lastVersion}},
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
		{"PUBLISH": {db.lastVersionChannelKey, lastVersion}},
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
	defer func(startTime time.Time) {
		recordOperation(ctx, startTime, "clear_deleted", opErr)
	}(time.Now())
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

// signalWithPubSub receives event from redis and send signal to the channel.
func (db *DB) signalWithPubSub(ctx context.Context, s *signal.Signal) {
	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 0

	// loop until the db is closed or the context is Done. We use exp backoff on errors.
	wait := time.After(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-db.closed:
			return
		case <-wait:
		}
		db.signalWithPubSubOnce(ctx, s, bo)

		wait = time.After(bo.NextBackOff())
	}
}

func (db *DB) signalWithPubSubOnce(ctx context.Context, s *signal.Signal, bo backoff.BackOff) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// get a connection from the pub sub tracker to make sure we aren't leaking connections
	conn, err := db.pubSubTracker.Get(ctx)
	if err != nil {
		log.Error().Err(err).Msg("failed to get redis connection")
		return
	}
	go func() {
		select {
		case <-ctx.Done():
		case <-db.closed:
		}
		_ = conn.Close()
	}()

	// subscribe to pubsub
	err = conn.Subscribe(db.lastVersionChannelKey)
	if err != nil {
		log.Error().Err(err).Msg("failed to subscribe to redis channel")
		return
	}

	for {
		switch v := conn.Receive().(type) {
		case redis.Message:
			log.Debug().Str("action", string(v.Data)).Msg("got redis message")
			recordOperation(ctx, time.Now(), "sub_received", nil)

			// reset the backoff since we got a successful result
			bo.Reset()

			// trigger the signal
			s.Broadcast()
		case error:
			if strings.Contains(v.Error(), "use of closed network connection") {
				return
			}
			log.Error().Err(v).Msg("failed to receive from redis channel")
			return
		}
	}
}

// Watch returns a channel to the caller which will send an empty struct any time the last version changes.
func (db *DB) Watch(ctx context.Context) <-chan struct{} {
	// create a new signal that will be used by the caller.
	s := signal.New()
	ch := s.Bind()

	// listen for pubsub events
	pubSubSignal := signal.New()
	pubSubCh := pubSubSignal.Bind()
	go db.signalWithPubSub(ctx, pubSubSignal)
	go func() {
		defer s.Unbind(ch)
		defer pubSubSignal.Unbind(pubSubCh)

		// force a recheck every 30 seconds
		ticker := time.NewTicker(time.Second * 30)
		defer ticker.Stop()

		var lastVersion int64
		for {
			select {
			case <-ctx.Done():
				return
			case <-db.closed:
				return
			case <-ticker.C: // forced re-check
			case <-pubSubCh: // change detected via pubsub
			}

			if v, err := db.getLastVersion(ctx); err != nil {
				log.Error().Err(err).Msg("redis: failed to get last version")
			} else if v != lastVersion {
				lastVersion = v
				s.Broadcast()
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

func (db *DB) getLastVersion(ctx context.Context) (int64, error) {
	c, err := db.pool.GetContext(ctx)
	if err != nil {
		return 0, err
	}
	defer c.Close()

	return redis.Int64(c.Do("GET", db.lastVersionKey))
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

func (db *DB) dial(ctx context.Context) (redis.Conn, error) {
	return redis.DialURL(db.rawURL, redis.DialTLSConfig(db.tlsConfig))
}

func recordOperation(ctx context.Context, startTime time.Time, operation string, err error) {
	metrics.RecordStorageOperation(ctx, &metrics.StorageOperationTags{
		Operation: operation,
		Error:     err,
		Backend:   Name,
	}, time.Since(startTime))
}
