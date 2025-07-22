package inmemory

import (
	"context"
	"maps"
	"slices"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

func (backend *Backend) iterateLatestRecords(
	ctx context.Context,
	recordType string,
	expr storage.FilterExpression,
) storage.RecordIterator {
	return func(yield func(*databroker.Record, error) bool) {
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
			select {
			case <-ctx.Done():
				return
			default:
			}

			backend.mu.RLock()
			co, ok := backend.lookup[recordType]
			if ok {
				records, err = co.List(expr)
			} else {
				records, err = nil, nil
			}
			backend.mu.RUnlock()

			if err != nil {
				yield(nil, err)
				return
			}

			for _, record := range records {
				if !yield(record, nil) {
					return
				}
			}
		}
	}
}
