package postgres

import (
	"context"

	"github.com/pomerium/pomerium/pkg/contextutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

func (backend *Backend) iterateChangedRecords(
	ctx context.Context,
	recordType string,
	serverVersion, recordVersion uint64,
	wait bool,
) storage.RecordIterator {
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	return func(yield func(*databroker.Record, error) bool) {
		defer cancel()

		currentServerVersion, pool, err := backend.init(ctx)
		if err != nil {
			yield(nil, err)
			return
		} else if currentServerVersion != serverVersion {
			yield(nil, storage.ErrInvalidServerVersion)
			return
		}

		changed := backend.onRecordChange.Bind()
		defer backend.onRecordChange.Unbind(changed)

		for {
			record, err := getNextChangedRecord(
				ctx,
				pool,
				recordType,
				recordVersion,
			)
			if err != nil && !isNotFound(err) {
				yield(nil, err)
				return
			}

			if record != nil {
				recordVersion = max(recordVersion, record.GetVersion())
				if !yield(record, nil) {
					return
				}
				continue
			}

			if !wait {
				return
			}

			select {
			case <-ctx.Done():
				yield(nil, context.Cause(ctx))
				return
			case <-changed:
			}
		}
	}
}

func (backend *Backend) iterateLatestRecords(
	ctx context.Context,
	expr storage.FilterExpression,
) storage.RecordIterator {
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	return func(yield func(*databroker.Record, error) bool) {
		defer cancel()

		_, pool, err := backend.init(ctx)
		if err != nil {
			yield(nil, err)
			return
		}

		for offset := 0; ; offset += recordBatchSize {
			records, err := listRecords(ctx, pool, expr, offset, recordBatchSize)
			if err != nil {
				yield(nil, err)
				return
			}

			if len(records) == 0 {
				break
			}

			for _, record := range records {
				if !yield(record, nil) {
					return
				}
			}
		}
	}
}
