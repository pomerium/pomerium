// Package redis implements the storage.Backend interface for redis.
package redis

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	redis "github.com/go-redis/redis/v8"
	"github.com/golang/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// Name of the storage backend.
const Name = config.StorageRedisName

const (
	maxTransactionRetries = 100
	watchPollInterval     = 30 * time.Second
)

// custom errors
var (
	ErrExceededMaxRetries = errors.New("redis: transaction reached maximum number of retries")
)

// DB implements the storage.Backend on top of redis.
type DB struct {
	cfg *dbConfig

	client *redis.Client

	closeOnce sync.Once
	closed    chan struct{}
}

// New creates a new redis storage backend.
func New(rawURL string, options ...Option) (*DB, error) {
	db := &DB{
		cfg:    getConfig(options...),
		closed: make(chan struct{}),
	}
	opts, err := redis.ParseURL(rawURL)
	if err != nil {
		return nil, err
	}
	// when using TLS, the TLS config will not be set to nil, in which case we replace it with our own
	if opts.TLSConfig != nil {
		opts.TLSConfig = db.cfg.tls
	}
	db.client = redis.NewClient(opts)
	metrics.AddRedisMetrics(db.client.PoolStats)
	return db, nil
}

// ClearDeleted clears all the deleted records older than the cutoff time.
func (db *DB) ClearDeleted(ctx context.Context, cutoff time.Time) {
	var err error

	_, span := trace.StartSpan(ctx, "databroker.redis.ClearDeleted")
	defer span.End()
	defer func(start time.Time) { recordOperation(ctx, start, "clear_deleted", err) }(time.Now())

	ids, _ := db.client.SMembers(ctx, formatDeletedSetKey(db.cfg.recordType)).Result()
	records, _ := redisGetRecords(ctx, db.client, db.cfg.recordType, ids)
	_, err = db.client.Pipelined(ctx, func(p redis.Pipeliner) error {
		for _, record := range records {
			if record.GetDeletedAt().AsTime().Before(cutoff) {
				p.HDel(ctx, formatRecordsKey(db.cfg.recordType), record.GetId())
				p.ZRem(ctx, formatVersionSetKey(db.cfg.recordType), record.GetId())
				p.SRem(ctx, formatDeletedSetKey(db.cfg.recordType), record.GetId())
			}
		}
		return nil
	})
}

// Close closes the underlying redis connection and any watchers.
func (db *DB) Close() error {
	var err error
	db.closeOnce.Do(func() {
		err = db.client.Close()
		close(db.closed)
	})
	return err
}

// Delete marks a record as deleted.
func (db *DB) Delete(ctx context.Context, id string) (err error) {
	_, span := trace.StartSpan(ctx, "databroker.redis.Delete")
	defer span.End()
	defer func(start time.Time) { recordOperation(ctx, start, "delete", err) }(time.Now())

	var record *databroker.Record
	err = db.incrementVersion(ctx,
		func(tx *redis.Tx, version int64) error {
			var err error
			record, err = redisGetRecord(ctx, tx, db.cfg.recordType, id)
			if errors.Is(err, redis.Nil) {
				// nothing to do, as the record doesn't exist
				return nil
			} else if err != nil {
				return err
			}

			// mark it as deleted
			record.DeletedAt = timestamppb.Now()

			return nil
		},
		func(p redis.Pipeliner, version int64) error {
			err := redisSetRecord(ctx, p, db.cfg.recordType, record)
			if err != nil {
				return err
			}

			// add it to the collection of deleted entries
			p.SAdd(ctx, formatDeletedSetKey(db.cfg.recordType), record.GetId())
			return nil
		})
	return err
}

// Get gets a record.
func (db *DB) Get(ctx context.Context, id string) (record *databroker.Record, err error) {
	_, span := trace.StartSpan(ctx, "databroker.redis.Get")
	defer span.End()
	defer func(start time.Time) { recordOperation(ctx, start, "get", err) }(time.Now())

	record, err = redisGetRecord(ctx, db.client, db.cfg.recordType, id)
	return record, err
}

// List lists all the records changed since the sinceVersion. Records are sorted in version order.
func (db *DB) List(ctx context.Context, sinceVersion string) (records []*databroker.Record, err error) {
	_, span := trace.StartSpan(ctx, "databroker.redis.List")
	defer span.End()
	defer func(start time.Time) { recordOperation(ctx, start, "list", err) }(time.Now())

	var ids []string
	ids, err = redisListIDsSince(ctx, db.client, db.cfg.recordType, sinceVersion)
	if err != nil {
		return nil, err
	}
	records, err = redisGetRecords(ctx, db.client, db.cfg.recordType, ids)
	return records, err
}

// Put updates a record.
func (db *DB) Put(ctx context.Context, id string, data *anypb.Any) (err error) {
	_, span := trace.StartSpan(ctx, "databroker.redis.Put")
	defer span.End()
	defer func(start time.Time) { recordOperation(ctx, start, "put", err) }(time.Now())

	var record *databroker.Record
	err = db.incrementVersion(ctx,
		func(tx *redis.Tx, version int64) error {
			var err error
			record, err = redisGetRecord(ctx, db.client, db.cfg.recordType, id)
			if errors.Is(err, redis.Nil) {
				record = new(databroker.Record)
				record.CreatedAt = timestamppb.Now()
			} else if err != nil {
				return err
			}

			record.ModifiedAt = timestamppb.Now()
			record.Type = db.cfg.recordType
			record.Id = id
			record.Data = data
			record.Version = formatVersion(version)

			return nil
		},
		func(p redis.Pipeliner, version int64) error {
			return redisSetRecord(ctx, p, db.cfg.recordType, record)
		})
	return err
}

// Watch returns a channel that is signaled any time the last version is incremented (ie on Put/Delete).
func (db *DB) Watch(ctx context.Context) <-chan struct{} {
	s := signal.New()
	ch := s.Bind()
	go func() {
		defer s.Unbind(ch)
		defer close(ch)

		// force a check
		poll := time.NewTicker(watchPollInterval)
		defer poll.Stop()

		// use pub/sub for quicker notify
		pubsub := db.client.Subscribe(ctx, formatLastVersionChannelKey(db.cfg.recordType))
		defer func() { _ = pubsub.Close() }()
		pubsubCh := pubsub.Channel()

		var lastVersion int64

		for {
			v, err := redisGetLastVersion(ctx, db.client, db.cfg.recordType)
			if err != nil {
				log.Error().Err(err).Msg("redis: error retrieving last version")
			} else if v != lastVersion {
				// don't broadcast the first time
				if lastVersion != 0 {
					s.Broadcast()
				}
				lastVersion = v
			}

			select {
			case <-ctx.Done():
				return
			case <-db.closed:
				return
			case <-poll.C:
			case <-pubsubCh:
				// re-check
			}
		}
	}()
	return ch
}

// incrementVersion increments the last version key, runs the code in `query`, then attempts to commit the code in
// `commit`. If the last version changes in the interim, we will retry the transaction.
func (db *DB) incrementVersion(ctx context.Context,
	query func(tx *redis.Tx, version int64) error,
	commit func(p redis.Pipeliner, version int64) error,
) error {
	// code is modeled on https://pkg.go.dev/github.com/go-redis/redis/v8#example-Client.Watch
	txf := func(tx *redis.Tx) error {
		version, err := redisGetLastVersion(ctx, tx, db.cfg.recordType)
		if err != nil {
			return err
		}
		version++

		err = query(tx, version)
		if err != nil {
			return err
		}

		// the `commit` code is run in a transaction so that the EXEC cmd will run for the original redis watch
		_, err = tx.TxPipelined(ctx, func(p redis.Pipeliner) error {
			err := commit(p, version)
			if err != nil {
				return err
			}
			p.Set(ctx, formatLastVersionKey(db.cfg.recordType), version, 0)
			p.Publish(ctx, formatLastVersionChannelKey(db.cfg.recordType), version)
			return nil
		})
		return err
	}

	for i := 0; i < maxTransactionRetries; i++ {
		err := db.client.Watch(ctx, txf, formatLastVersionKey(db.cfg.recordType))
		if errors.Is(err, redis.TxFailedErr) {
			continue // retry
		} else if err != nil {
			return err
		}

		return nil // tx was successful
	}

	return ErrExceededMaxRetries
}

func redisGetLastVersion(ctx context.Context, c redis.Cmdable, recordType string) (int64, error) {
	version, err := c.Get(ctx, formatLastVersionKey(recordType)).Int64()
	if errors.Is(err, redis.Nil) {
		version = 0
	} else if err != nil {
		return 0, err
	}
	return version, nil
}

func redisGetRecord(ctx context.Context, c redis.Cmdable, recordType string, id string) (*databroker.Record, error) {
	records, err := redisGetRecords(ctx, c, recordType, []string{id})
	if err != nil {
		return nil, err
	} else if len(records) < 1 {
		return nil, redis.Nil
	}
	return records[0], nil
}

func redisGetRecords(ctx context.Context, c redis.Cmdable, recordType string, ids []string) ([]*databroker.Record, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	results, err := c.HMGet(ctx, formatRecordsKey(recordType), ids...).Result()
	if err != nil {
		return nil, err
	}

	records := make([]*databroker.Record, 0, len(results))
	for _, result := range results {
		// results are returned as either nil or a string
		if result == nil {
			continue
		}
		rawstr, ok := result.(string)
		if !ok {
			continue
		}
		var record databroker.Record
		err := proto.Unmarshal([]byte(rawstr), &record)
		if err != nil {
			continue
		}
		records = append(records, &record)
	}
	return records, nil
}

func redisListIDsSince(ctx context.Context,
	c redis.Cmdable, recordType string,
	sinceVersion string,
) ([]string, error) {
	v, err := strconv.ParseInt(sinceVersion, 16, 64)
	if err != nil {
		v = 0
	}
	rng := &redis.ZRangeBy{
		Min: fmt.Sprintf("(%d", v),
		Max: "+inf",
	}
	return c.ZRangeByScore(ctx, formatVersionSetKey(recordType), rng).Result()
}

func redisSetRecord(ctx context.Context, p redis.Pipeliner, recordType string, record *databroker.Record) error {
	v, err := strconv.ParseInt(record.GetVersion(), 16, 64)
	if err != nil {
		v = 0
	}

	raw, err := proto.Marshal(record)
	if err != nil {
		return err
	}

	// store the record in the hash
	p.HSet(ctx, formatRecordsKey(recordType), record.GetId(), string(raw))
	// set its score for sorting by version
	p.ZAdd(ctx, formatVersionSetKey(recordType), &redis.Z{
		Score:  float64(v),
		Member: record.GetId(),
	})

	return nil
}

func formatDeletedSetKey(recordType string) string {
	return fmt.Sprintf("%s_deleted_set", recordType)
}

func formatLastVersionChannelKey(recordType string) string {
	return fmt.Sprintf("%s_last_version_ch", recordType)
}

func formatLastVersionKey(recordType string) string {
	return fmt.Sprintf("%s_last_version", recordType)
}

func formatRecordsKey(recordType string) string {
	return recordType
}

func formatVersion(version int64) string {
	return fmt.Sprintf("%012d", version)
}

func formatVersionSetKey(recordType string) string {
	return fmt.Sprintf("%s_version_set", recordType)
}

func recordOperation(ctx context.Context, startTime time.Time, operation string, err error) {
	metrics.RecordStorageOperation(ctx, &metrics.StorageOperationTags{
		Operation: operation,
		Error:     err,
		Backend:   Name,
	}, time.Since(startTime))
}
