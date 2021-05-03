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
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

const (
	maxTransactionRetries = 100
	watchPollInterval     = 30 * time.Second

	// we rely on transactions in redis, so all redis-cluster keys need to be
	// on the same node. Using a `hash tag` gives us this capability.
	serverVersionKey = "{pomerium_v3}.server_version"
	lastVersionKey   = "{pomerium_v3}.last_version"
	lastVersionChKey = "{pomerium_v3}.last_version_ch"
	recordHashKey    = "{pomerium_v3}.records"
	changesSetKey    = "{pomerium_v3}.changes"
	optionsKey       = "{pomerium_v3}.options"

	recordTypeChangesKeyTpl = "{pomerium_v3}.changes.%s"
	leaseKeyTpl             = "{pomerium_v3}.lease.%s"
)

// custom errors
var (
	ErrExceededMaxRetries = errors.New("redis: transaction reached maximum number of retries")
)

// Backend implements the storage.Backend on top of redis.
//
// What's stored:
//
// - last_version: an integer recordVersion number
// - last_version_ch: a PubSub channel for recordVersion number updates
// - records: a Hash of records. The hash key is {recordType}/{recordID}, the hash value the protobuf record.
// - changes: a Sorted Set of all the changes. The score is the recordVersion number, the member the protobuf record.
// - options: a Hash of options. The hash key is {recordType}, the hash value the protobuf options.
// - changes.{recordType}: a Sorted Set of the changes for a record type. The score is the current time,
//   the value the record id.
//
// Records stored in these keys are typically encrypted.
type Backend struct {
	cfg *config

	client   redis.UniversalClient
	onChange *signal.Signal

	closeOnce sync.Once
	closed    chan struct{}
}

// New creates a new redis storage backend.
func New(rawURL string, options ...Option) (*Backend, error) {
	ctx := context.TODO()
	cfg := getConfig(options...)
	backend := &Backend{
		cfg:      cfg,
		closed:   make(chan struct{}),
		onChange: signal.New(),
	}
	var err error
	backend.client, err = newClientFromURL(rawURL, backend.cfg.tls)
	if err != nil {
		return nil, err
	}
	metrics.AddRedisMetrics(backend.client.PoolStats)
	go backend.listenForVersionChanges(ctx)
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

				backend.removeChangesBefore(ctx, time.Now().Add(-cfg.expiry))
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
func (backend *Backend) GetAll(ctx context.Context) (records []*databroker.Record, versions *databroker.Versions, err error) {
	ctx, span := trace.StartSpan(ctx, "databroker.redis.GetAll")
	defer span.End()
	defer func(start time.Time) { recordOperation(ctx, start, "getall", err) }(time.Now())

	versions = new(databroker.Versions)

	versions.ServerVersion, err = backend.getOrCreateServerVersion(ctx)
	if err != nil {
		return nil, nil, err
	}

	p := backend.client.Pipeline()
	lastVersionCmd := p.Get(ctx, lastVersionKey)
	resultsCmd := p.HVals(ctx, recordHashKey)
	_, err = p.Exec(ctx)
	if errors.Is(err, redis.Nil) {
		// nil is returned when there are no records
		return nil, versions, nil
	} else if err != nil {
		return nil, nil, fmt.Errorf("redis: error beginning GetAll pipeline: %w", err)
	}

	versions.LatestRecordVersion, err = lastVersionCmd.Uint64()
	if errors.Is(err, redis.Nil) {
	} else if err != nil {
		return nil, nil, fmt.Errorf("redis: error retrieving GetAll latest record version: %w", err)
	}

	var results []string
	results, err = resultsCmd.Result()
	if err != nil {
		return nil, nil, fmt.Errorf("redis: error retrieving GetAll records: %w", err)
	}

	for _, result := range results {
		var record databroker.Record
		err := proto.Unmarshal([]byte(result), &record)
		if err != nil {
			log.Warn(ctx).Err(err).Msg("redis: invalid record detected")
			continue
		}
		records = append(records, &record)
	}
	return records, versions, nil
}

// GetOptions gets the options for the given record type.
func (backend *Backend) GetOptions(ctx context.Context, recordType string) (*databroker.Options, error) {
	raw, err := backend.client.HGet(ctx, optionsKey, recordType).Result()
	if err == redis.Nil {
		// treat no options as an empty set of options
		return new(databroker.Options), nil
	} else if err != nil {
		return nil, err
	}

	var options databroker.Options
	err = proto.Unmarshal([]byte(raw), &options)
	if err != nil {
		return nil, err
	}

	return &options, nil
}

// Lease acquires or renews a lease.
func (backend *Backend) Lease(ctx context.Context, leaseName, leaseID string, ttl time.Duration) (bool, error) {
	acquired := false
	key := getLeaseKey(leaseName)
	err := backend.client.Watch(ctx, func(tx *redis.Tx) error {
		currentID, err := tx.Get(ctx, key).Result()
		if errors.Is(err, redis.Nil) {
			// lease hasn't been set yet
		} else if err != nil {
			return err
		} else if leaseID != currentID {
			// lease has already been taken
			return nil
		}

		_, err = tx.Pipelined(ctx, func(p redis.Pipeliner) error {
			if ttl <= 0 {
				p.Del(ctx, key)
			} else {
				p.Set(ctx, key, leaseID, ttl)
			}
			return nil
		})
		if err != nil {
			return err
		}
		acquired = ttl > 0
		return nil
	}, key)
	// if the transaction failed someone else must've acquired the lease
	if errors.Is(err, redis.TxFailedErr) {
		acquired = false
		err = nil
	}
	return acquired, err
}

// Put puts a record into redis.
func (backend *Backend) Put(ctx context.Context, record *databroker.Record) (serverVersion uint64, err error) {
	ctx, span := trace.StartSpan(ctx, "databroker.redis.Put")
	defer span.End()
	defer func(start time.Time) { recordOperation(ctx, start, "put", err) }(time.Now())

	serverVersion, err = backend.getOrCreateServerVersion(ctx)
	if err != nil {
		return serverVersion, err
	}

	err = backend.put(ctx, record)
	if err != nil {
		return serverVersion, err
	}

	err = backend.enforceOptions(ctx, record.GetType())
	if err != nil {
		return serverVersion, err
	}

	return serverVersion, nil
}

// SetOptions sets the options for the given record type.
func (backend *Backend) SetOptions(ctx context.Context, recordType string, options *databroker.Options) error {
	ctx, span := trace.StartSpan(ctx, "databroker.redis.SetOptions")
	defer span.End()

	bs, err := proto.Marshal(options)
	if err != nil {
		return err
	}

	// update the options in the hash set
	err = backend.client.HSet(ctx, optionsKey, recordType, bs).Err()
	if err != nil {
		return err
	}

	// possibly re-enforce options
	err = backend.enforceOptions(ctx, recordType)
	if err != nil {
		return err
	}

	return nil
}

// Sync returns a record stream of any records changed after the specified recordVersion.
func (backend *Backend) Sync(ctx context.Context, serverVersion, recordVersion uint64) (storage.RecordStream, error) {
	return newRecordStream(ctx, backend, serverVersion, recordVersion), nil
}

func (backend *Backend) put(ctx context.Context, record *databroker.Record) error {
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
			p.ZAdd(ctx, getRecordTypeChangesKey(record.GetType()), &redis.Z{
				Score:  float64(record.GetModifiedAt().GetSeconds()),
				Member: record.GetId(),
			})
			return nil
		})
}

// enforceOptions enforces the options for the given record type.
func (backend *Backend) enforceOptions(ctx context.Context, recordType string) error {
	ctx, span := trace.StartSpan(ctx, "databroker.redis.enforceOptions")
	defer span.End()

	options, err := backend.GetOptions(ctx, recordType)
	if err != nil {
		return err
	}

	// nothing to do if capacity isn't set
	if options.Capacity == nil {
		return nil
	}

	key := getRecordTypeChangesKey(recordType)

	// enforce capacity by retrieving the size of the collection and removing excess items, oldest first

	sz, err := backend.client.ZCard(ctx, key).Uint64()
	if err == redis.Nil {
		return nil
	} else if err != nil {
		return err
	}

	removeCnt := sz - *options.Capacity
	if removeCnt <= 0 {
		// nothing to do
		return nil
	}

	// remove the oldest records
	zs, err := backend.client.ZPopMin(ctx, key, int64(removeCnt)).Result()
	if err != nil {
		return err
	}

	for _, z := range zs {
		recordID := z.Member.(string)

		record, err := backend.Get(ctx, recordType, recordID)
		if errors.Is(err, storage.ErrNotFound) {
			continue
		} else if err != nil {
			return err
		}

		// mark the record as deleted and re-submit
		record.DeletedAt = timestamppb.Now()
		err = backend.put(ctx, record)
		if err != nil {
			return err
		}
	}

	return nil
}

// incrementVersion increments the last recordVersion key, runs the code in `query`, then attempts to commit the code in
// `commit`. If the last recordVersion changes in the interim, we will retry the transaction.
func (backend *Backend) incrementVersion(ctx context.Context,
	query func(tx *redis.Tx, recordVersion uint64) error,
	commit func(p redis.Pipeliner, recordVersion uint64) error,
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

	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 0
	for i := 0; i < maxTransactionRetries; i++ {
		err := backend.client.Watch(ctx, txf, lastVersionKey)
		if errors.Is(err, redis.TxFailedErr) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(bo.NextBackOff()):
			}
			continue // retry
		} else if err != nil {
			return err
		}

		return nil // tx was successful
	}

	return ErrExceededMaxRetries
}

func (backend *Backend) listenForVersionChanges(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
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
				backend.onChange.Broadcast(ctx)
			}
		}
	}
}

func (backend *Backend) removeChangesBefore(ctx context.Context, cutoff time.Time) {
	for {
		cmd := backend.client.ZRangeByScore(ctx, changesSetKey, &redis.ZRangeBy{
			Min:    "-inf",
			Max:    "+inf",
			Offset: 0,
			Count:  1,
		})
		results, err := cmd.Result()
		if err != nil {
			log.Error(ctx).Err(err).Msg("redis: error retrieving changes for expiration")
			return
		}

		// nothing left to do
		if len(results) == 0 {
			return
		}

		var record databroker.Record
		err = proto.Unmarshal([]byte(results[0]), &record)
		if err != nil {
			log.Warn(ctx).Err(err).Msg("redis: invalid record detected")
			record.ModifiedAt = timestamppb.New(cutoff.Add(-time.Second)) // set the modified so will delete it
		}

		// if the record's modified timestamp is after the cutoff, we're all done, so break
		if record.GetModifiedAt().AsTime().After(cutoff) {
			break
		}

		// remove the record
		err = backend.client.ZRem(ctx, changesSetKey, results[0]).Err()
		if err != nil {
			log.Error(ctx).Err(err).Msg("redis: error removing member")
			return
		}
	}
}

func (backend *Backend) getOrCreateServerVersion(ctx context.Context) (serverVersion uint64, err error) {
	serverVersion, err = backend.client.Get(ctx, serverVersionKey).Uint64()
	// if the server version hasn't been set yet, set it to a random value and immediately retrieve it
	// this should properly handle a data race by only setting the key if it doesn't already exist
	if errors.Is(err, redis.Nil) {
		_, _ = backend.client.SetNX(ctx, serverVersionKey, cryptutil.NewRandomUInt64(), 0).Result()
		serverVersion, err = backend.client.Get(ctx, serverVersionKey).Uint64()
	}
	if err != nil {
		return 0, fmt.Errorf("redis: error retrieving server version: %w", err)
	}
	return serverVersion, err
}

func getLeaseKey(leaseName string) string {
	return fmt.Sprintf(leaseKeyTpl, leaseName)
}

func getRecordTypeChangesKey(recordType string) string {
	return fmt.Sprintf(recordTypeChangesKeyTpl, recordType)
}

func getHashKey(recordType, id string) (key, field string) {
	return recordHashKey, fmt.Sprintf("%s/%s", recordType, id)
}
