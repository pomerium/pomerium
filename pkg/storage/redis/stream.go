package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

func newSyncRecordStream(
	ctx context.Context,
	backend *Backend,
	serverVersion uint64,
	recordVersion uint64,
) storage.RecordStream {
	changed := backend.onChange.Bind()
	return storage.NewRecordStream(ctx, backend.closed, []storage.RecordStreamGenerator{
		// 1. stream all record changes
		func(ctx context.Context, block bool) (*databroker.Record, error) {
			ticker := time.NewTicker(watchPollInterval)
			defer ticker.Stop()

			for {
				currentServerVersion, err := backend.getOrCreateServerVersion(ctx)
				if err != nil {
					return nil, err
				}
				if serverVersion != currentServerVersion {
					return nil, storage.ErrInvalidServerVersion
				}

				record, err := nextChangedRecord(ctx, backend, &recordVersion)
				if err == nil {
					return record, nil
				} else if !errors.Is(err, storage.ErrStreamDone) {
					return nil, err
				}

				if !block {
					return nil, storage.ErrStreamDone
				}

				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-ticker.C:
				case <-changed:
				}
			}
		},
	}, func() {
		backend.onChange.Unbind(changed)
	})
}

func newSyncLatestRecordStream(
	ctx context.Context,
	backend *Backend,
) storage.RecordStream {
	var recordVersion, cursor uint64
	scannedOnce := false
	var scannedRecords []*databroker.Record
	return storage.NewRecordStream(ctx, backend.closed, []storage.RecordStreamGenerator{
		// 1. get the current record version
		func(ctx context.Context, block bool) (*databroker.Record, error) {
			var err error
			recordVersion, err = backend.client.Get(ctx, lastVersionKey).Uint64()
			if err != nil {
				return nil, err
			}
			return nil, storage.ErrStreamDone
		},
		// 2. stream all the records
		func(ctx context.Context, block bool) (*databroker.Record, error) {
			for {
				if len(scannedRecords) > 0 {
					record := scannedRecords[0]
					scannedRecords = scannedRecords[1:]
					return record, nil
				}

				// the cursor is reset to 0 after iteration is complete
				if scannedOnce && cursor == 0 {
					return nil, storage.ErrStreamDone
				}

				var err error
				scannedRecords, err = nextScannedRecords(ctx, backend, &cursor)
				if err != nil {
					return nil, err
				}

				scannedOnce = true
			}
		},
		// 3. stream any records which have been updated in the interim
		func(ctx context.Context, block bool) (*databroker.Record, error) {
			return nextChangedRecord(ctx, backend, &recordVersion)
		},
	}, nil)
}

func nextScannedRecords(ctx context.Context, backend *Backend, cursor *uint64) ([]*databroker.Record, error) {
	var values []string
	var err error
	values, *cursor, err = backend.client.HScan(ctx, recordHashKey, *cursor, "", 0).Result()
	if errors.Is(err, redis.Nil) {
		return nil, storage.ErrStreamDone
	} else if err != nil {
		return nil, err
	} else if len(values) == 0 {
		return nil, storage.ErrStreamDone
	}

	var records []*databroker.Record
	for i := 1; i < len(values); i += 2 {
		var record databroker.Record
		err := proto.Unmarshal([]byte(values[i]), &record)
		if err != nil {
			log.Warn(ctx).Err(err).Msg("redis: invalid record detected")
			continue
		}
		records = append(records, &record)
	}
	return records, nil
}

func nextChangedRecord(ctx context.Context, backend *Backend, recordVersion *uint64) (*databroker.Record, error) {
	for {
		cmd := backend.client.ZRangeByScore(ctx, changesSetKey, &redis.ZRangeBy{
			Min:    fmt.Sprintf("(%d", *recordVersion),
			Max:    "+inf",
			Offset: 0,
			Count:  1,
		})
		results, err := cmd.Result()
		if errors.Is(err, redis.Nil) {
			return nil, storage.ErrStreamDone
		} else if err != nil {
			return nil, err
		} else if len(results) == 0 {
			return nil, storage.ErrStreamDone
		}

		result := results[0]
		var record databroker.Record
		err = proto.Unmarshal([]byte(result), &record)
		*recordVersion++
		if err == nil {
			return &record, nil
		}
		log.Warn(ctx).Err(err).Msg("redis: invalid record detected")
	}
}
