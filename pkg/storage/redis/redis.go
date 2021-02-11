// Package redis implements the storage.Backend interface for redis.
package redis

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	redis "github.com/go-redis/redis/v8"
	"github.com/golang/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

const (
	maxTransactionRetries = 100
	watchPollInterval     = 30 * time.Second

	lastVersionKey   = "pomerium.last_version"
	lastVersionChKey = "pomerium.last_version_ch"
	recordHashKey    = "pomerium.records"
	changesSetKey    = "pomerium.changes"
)

// custom errors
var (
	ErrExceededMaxRetries = errors.New("redis: transaction reached maximum number of retries")
)

// Backend implements the storage.Backend on top of redis.
type Backend struct {
	cfg *config

	client   *redis.Client
	onChange *signal.Signal

	closeOnce sync.Once
	closed    chan struct{}
}

// New creates a new redis storage backend.
func New(rawURL string, options ...Option) (*Backend, error) {
	cfg := getConfig(options...)
	backend := &Backend{
		cfg:      cfg,
		closed:   make(chan struct{}),
		onChange: signal.New(),
	}
	opts, err := redis.ParseURL(rawURL)
	if err != nil {
		return nil, err
	}
	// when using TLS, the TLS config will not be set to nil, in which case we replace it with our own
	if opts.TLSConfig != nil {
		opts.TLSConfig = backend.cfg.tls
	}
	backend.client = redis.NewClient(opts)
	metrics.AddRedisMetrics(backend.client.PoolStats)
	go backend.listenForVersionChanges()
	if cfg.expiry != 0 {
		go func() {
			ticker := time.NewTicker(time.Minute)
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
	return backend, nil
}

// Close closes the underlying redis connection and any watchers.
func (backend *Backend) Close() error {
	var err error
	backend.closeOnce.Do(func() {
		err = backend.client.Close()
		close(backend.closed)
	})
	return err
}

// Get gets a record from redis.
func (backend *Backend) Get(ctx context.Context, recordType, id string) (_ *databroker.Record, err error) {
	_, span := trace.StartSpan(ctx, "databroker.redis.Get")
	defer span.End()
	defer func(start time.Time) { recordOperation(ctx, start, "get", err) }(time.Now())

	key, field := getHashKey(recordType, id)
	cmd := backend.client.HGet(ctx, key, field)
	raw, err := cmd.Result()
	if err == redis.Nil {
		return nil, storage.ErrNotFound
	} else if err != nil {
		return nil, err
	}

	var record databroker.Record
	err = proto.Unmarshal([]byte(raw), &record)
	if err != nil {
		return nil, err
	}

	return &record, nil
}

// GetAll gets all the records from redis.
func (backend *Backend) GetAll(ctx context.Context) (records []*databroker.Record, err error) {
	_, span := trace.StartSpan(ctx, "databroker.redis.GetAll")
	defer span.End()
	defer func(start time.Time) { recordOperation(ctx, start, "getall", err) }(time.Now())

	cmd := backend.client.HVals(ctx, recordHashKey)
	raws, err := cmd.Result()
	if err != nil {
		return nil, err
	}

	for _, raw := range raws {
		var record databroker.Record
		err := proto.Unmarshal([]byte(raw), &record)
		if err != nil {
			log.Warn().Err(err).Msg("redis: invalid record detected")
			continue
		}
		records = append(records, &record)
	}
	return records, nil
}

// Put puts a record into redis.
func (backend *Backend) Put(ctx context.Context, record *databroker.Record) (err error) {
	_, span := trace.StartSpan(ctx, "databroker.redis.Put")
	defer span.End()
	defer func(start time.Time) { recordOperation(ctx, start, "put", err) }(time.Now())

	return backend.incrementVersion(ctx,
		func(tx *redis.Tx, version uint64) error {
			record.ModifiedAt = timestamppb.Now()
			record.Version = version
			return nil
		},
		func(p redis.Pipeliner, version uint64) error {
			bs, err := proto.Marshal(record)
			if err != nil {
				return err
			}

			key, field := getHashKey(record.GetType(), record.GetId())
			if record.DeletedAt != nil {
				p.HDel(ctx, key, field)
			} else {
				p.HSet(ctx, key, field, bs)
			}
			p.ZAdd(ctx, changesSetKey, &redis.Z{
				Score:  float64(version),
				Member: bs,
			})
			return nil
		})
}

func (backend *Backend) Sync(ctx context.Context, version uint64) (storage.RecordStream, error) {
	return newRecordStream(ctx, backend, version), nil
}

// incrementVersion increments the last version key, runs the code in `query`, then attempts to commit the code in
// `commit`. If the last version changes in the interim, we will retry the transaction.
func (backend *Backend) incrementVersion(ctx context.Context,
	query func(tx *redis.Tx, version uint64) error,
	commit func(p redis.Pipeliner, version uint64) error,
) error {
	// code is modeled on https://pkg.go.dev/github.com/go-redis/redis/v8#example-Client.Watch
	txf := func(tx *redis.Tx) error {
		version, err := tx.Get(ctx, lastVersionKey).Uint64()
		if errors.Is(err, redis.Nil) {
			version = 0
		} else if err != nil {
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
			p.Set(ctx, lastVersionKey, version, 0)
			p.Publish(ctx, lastVersionChKey, version)
			return nil
		})
		return err
	}

	for i := 0; i < maxTransactionRetries; i++ {
		err := backend.client.Watch(ctx, txf, lastVersionKey)
		if errors.Is(err, redis.TxFailedErr) {
			time.Sleep(time.Millisecond * 10)
			continue // retry
		} else if err != nil {
			return err
		}

		return nil // tx was successful
	}

	return ErrExceededMaxRetries
}

func (backend *Backend) listenForVersionChanges() {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-backend.closed
		cancel()
	}()

	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 0

outer:
	for {
		pubsub := backend.client.Subscribe(ctx, lastVersionChKey)
		for {
			msg, err := pubsub.Receive(ctx)
			if err != nil {
				_ = pubsub.Close()
				select {
				case <-ctx.Done():
					return
				case <-time.After(bo.NextBackOff()):
				}
				continue outer
			}
			bo.Reset()

			switch msg.(type) {
			case *redis.Message:
				backend.onChange.Broadcast()
			}
		}
	}
}

func (backend *Backend) removeChangesBefore(cutoff time.Time) {
	ctx := context.Background()
	for {
		cmd := backend.client.ZRangeByScore(ctx, changesSetKey, &redis.ZRangeBy{
			Min:    "-inf",
			Max:    "+inf",
			Offset: 0,
			Count:  1,
		})
		raws, err := cmd.Result()
		if err != nil {
			log.Error().Err(err).Msg("redis: error retrieving changes for expiration")
			return
		}

		// nothing left to do
		if len(raws) == 0 {
			return
		}

		var record databroker.Record
		err = proto.Unmarshal([]byte(raws[0]), &record)
		if err != nil {
			log.Warn().Err(err).Msg("redis: invalid record detected")
			record.ModifiedAt = timestamppb.New(cutoff.Add(-time.Second)) // set the modified so will delete it
		}

		// if the record's modified timestamp is after the cutoff, we're all done, so break
		if record.GetModifiedAt().AsTime().After(cutoff) {
			break
		}

		// remove the record
		err = backend.client.ZRem(ctx, changesSetKey, raws[0]).Err()
		if err != nil {
			log.Error().Err(err).Msg("redis: error removing member")
			return
		}
	}
}

func getHashKey(recordType, id string) (key, field string) {
	return recordHashKey, fmt.Sprintf("%s/%s", recordType, id)
}
