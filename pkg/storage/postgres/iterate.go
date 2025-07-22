package postgres

import (
	"context"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

func (backend *Backend) iterateLatestRecords(
	ctx context.Context,
	expr storage.FilterExpression,
) storage.RecordIterator {
	return func(yield func(*databroker.Record, error) bool) {
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
