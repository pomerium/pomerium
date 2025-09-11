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
	serverVersion, afterRecordVersion uint64,
	wait bool,
) storage.RecordIterator {
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx, backend.iteratorCanceler.Context())
	return func(yield func(*databroker.Record, error) bool) {
		defer cancel(nil)

		currentServerVersion, pool, err := backend.init(ctx)
		if err != nil {
			yield(nil, err)
			return
		} else if currentServerVersion != serverVersion {
			yield(nil, storage.ErrInvalidServerVersion)
			return
		}

		earliestRecordVersion, _, err := getRecordVersionRange(ctx, backend.pool)
		if err != nil {
			yield(nil, err)
			return
		}
		if earliestRecordVersion > 0 && afterRecordVersion < (earliestRecordVersion-1) {
			yield(nil, storage.ErrInvalidRecordVersion)
			return
		}

		changed := backend.onRecordChange.Bind()
		defer backend.onRecordChange.Unbind(changed)

		for {
			records, err := listChangedRecordsAfter(
				ctx,
				pool,
				recordType,
				afterRecordVersion,
			)
			if err != nil {
				yield(nil, err)
				return
			}
			if len(records) > 0 {
				for _, record := range records {
					afterRecordVersion = max(afterRecordVersion, record.GetVersion())
					if !yield(record, nil) {
						return
					}
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
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx, backend.iteratorCanceler.Context())
	return func(yield func(*databroker.Record, error) bool) {
		defer cancel(nil)

		_, pool, err := backend.init(ctx)
		if err != nil {
			yield(nil, err)
			return
		}

		var lastRecordType, lastRecordID string
		for {
			records, err := listLatestRecordsAfter(ctx, pool, expr, lastRecordType, lastRecordID)
			if err != nil {
				yield(nil, err)
				return
			}

			if len(records) == 0 {
				break
			}

			for _, record := range records {
				lastRecordType = record.GetType()
				lastRecordID = record.GetId()
				if !yield(record, nil) {
					return
				}
			}
		}
	}
}
