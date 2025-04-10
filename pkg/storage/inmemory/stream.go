package inmemory

import (
	"context"
	"maps"
	"slices"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

func newSyncLatestRecordStream(
	ctx context.Context,
	backend *Backend,
	recordType string,
	expr storage.FilterExpression,
) (storage.RecordStream, error) {
	backend.mu.RLock()
	defer backend.mu.RUnlock()

	var recordTypes []string
	if recordType == "" {
		recordTypes = slices.Sorted(maps.Keys(backend.lookup))
	} else {
		recordTypes = []string{recordType}
	}

	var records []*databroker.Record
	for _, recordType := range recordTypes {
		co, ok := backend.lookup[recordType]
		if !ok {
			continue
		}
		rs, err := co.List(expr)
		if err != nil {
			return nil, err
		}
		records = append(records, rs...)
	}

	return storage.RecordListToStream(ctx, records), nil
}

func newSyncRecordStream(
	ctx context.Context,
	backend *Backend,
	recordType string,
	recordVersion uint64,
) storage.RecordStream {
	changed := backend.onChange.Bind()
	var ready []*databroker.Record
	return storage.NewRecordStream(ctx, backend.closed, []storage.RecordStreamGenerator{
		func(ctx context.Context, block bool) (*databroker.Record, error) {
			if len(ready) > 0 {
				record := ready[0]
				ready = ready[1:]
				return record, nil
			}

			for {
				ready = backend.getSince(recordType, recordVersion)

				if len(ready) > 0 {
					// records are sorted by version,
					// so update the local version to the last record
					recordVersion = ready[len(ready)-1].GetVersion()
					record := ready[0]
					ready = ready[1:]
					return record, nil
				} else if !block {
					return nil, storage.ErrStreamDone
				}

				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-changed:
				}
			}
		},
	}, func() {
		backend.onChange.Unbind(changed)
	})
}
