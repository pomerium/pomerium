package file

import (
	"context"
	"fmt"

	"github.com/pomerium/pomerium/pkg/contextutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

func (backend *Backend) iterateChangedRecords(
	ctx context.Context,
	recordType string,
	serverVersion, afterRecordVersion uint64,
	wait bool,
) storage.RecordIterator {
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	return func(yield func(*databrokerpb.Record, error) bool) {
		defer cancel(nil)

		changed := backend.onRecordChange.Bind()
		defer backend.onRecordChange.Unbind(changed)

		var currentServerVersion, earliestRecordVersion uint64
		err := backend.withReadOnlyTransaction(func(tx readOnlyTransaction) error {
			var err error
			currentServerVersion, err = metadataKeySpace.getServerVersion(tx)
			if err != nil {
				return fmt.Errorf("pebble: error getting server version: %w", err)
			}
			earliestRecordVersion, err = metadataKeySpace.getEarliestRecordVersion(tx)
			if err != nil {
				return fmt.Errorf("pebble: error getting earliest record version: %w", err)
			}
			return nil
		})
		if err != nil {
			yield(nil, err)
			return
		}

		if serverVersion != currentServerVersion {
			yield(nil, storage.ErrInvalidServerVersion)
			return
		} else if earliestRecordVersion > 0 && afterRecordVersion < (earliestRecordVersion-1) {
			yield(nil, storage.ErrInvalidRecordVersion)
			return
		}

		for {
			var records []*databrokerpb.Record
			err = backend.withReadOnlyTransaction(func(tx readOnlyTransaction) error {
				var err error
				records, err = listChangedRecordsAfter(tx, recordType, afterRecordVersion)
				return err
			})
			if err != nil {
				yield(nil, fmt.Errorf("pebble: error listing changed records: %w", err))
				return
			}

			if len(records) > 0 {
				for _, record := range records {
					if !yield(record, nil) {
						return
					}
					afterRecordVersion = max(afterRecordVersion, record.GetVersion())

					select {
					case <-ctx.Done():
						yield(nil, context.Cause(ctx))
						return
					default:
					}
				}
				continue
			}

			if !wait {
				break
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
	recordType string,
	filter storage.FilterExpression,
) storage.RecordIterator {
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx)
	return func(yield func(*databrokerpb.Record, error) bool) {
		defer cancel(nil)

		var records []*databrokerpb.Record
		err := backend.withReadOnlyTransaction(func(tx readOnlyTransaction) error {
			var err error
			records, err = listLatestRecords(tx, recordType, filter)
			return err
		})
		if err != nil {
			yield(nil, err)
			return
		}
		for _, record := range records {
			if !yield(record, nil) {
				return
			}

			select {
			case <-ctx.Done():
				yield(nil, context.Cause(ctx))
				return
			default:
			}
		}
	}
}
