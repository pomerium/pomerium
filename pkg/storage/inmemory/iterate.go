package inmemory

import (
	"context"
	"errors"
	"maps"
	"slices"

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

		backend.mu.RLock()
		earliestRecordVersion := backend.earliestRecordVersion
		currentServerVersion := backend.serverVersion
		backend.mu.RUnlock()
		var initErr error
		if serverVersion != currentServerVersion {
			initErr = storage.ErrInvalidServerVersion
		} else if earliestRecordVersion > 0 && afterRecordVersion < (earliestRecordVersion-1) {
			initErr = storage.ErrInvalidRecordVersion
		}
		ctrlRec := storage.ControlFrameRecord()
		if !yield(&ctrlRec, initErr) {
			return
		}
		if initErr != nil {
			return
		}

		changed := backend.onRecordChange.Bind()
		defer backend.onRecordChange.Unbind(changed)

		for {
			records := backend.listChangedRecordsAfter(recordType, afterRecordVersion)
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
				err := context.Cause(ctx)
				yield(nil, err)
				return
			case <-changed:
			}
		}
	}
}

func (backend *Backend) iterateLatestRecords(
	ctx context.Context,
	recordType string,
	expr storage.FilterExpression,
) storage.RecordIterator {
	ctx, cancel := contextutil.Merge(ctx, backend.closeCtx, backend.iteratorCanceler.Context())
	return func(yield func(*databroker.Record, error) bool) {
		defer cancel(nil)

		backend.mu.RLock()
		var recordTypes []string
		if recordType == "" {
			recordTypes = slices.Sorted(maps.Keys(backend.lookup))
		} else {
			recordTypes = []string{recordType}
		}
		backend.mu.RUnlock()

		var records []*databroker.Record
		var err error

		for _, recordType := range recordTypes {
			backend.mu.RLock()
			co, ok := backend.lookup[recordType]
			if ok {
				records, err = co.List(expr)
			} else {
				records, err = nil, nil
			}
			backend.mu.RUnlock()

			if errors.Is(err, storage.ErrNoSuchIndex) {
				return
			} else if err != nil {
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
}
