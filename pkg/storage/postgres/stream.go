package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pomerium/pomerium/pkg/contextutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

const recordBatchSize = 64

const watchPollInterval = 30 * time.Second

type changedRecordStream struct {
	backend       *Backend
	recordType    string
	recordVersion uint64

	ctx     context.Context
	cancel  context.CancelFunc
	record  *databroker.Record
	err     error
	ticker  *time.Ticker
	changed chan context.Context
}

func newChangedRecordStream(
	ctx context.Context,
	backend *Backend,
	recordType string,
	recordVersion uint64,
) storage.RecordStream {
	stream := &changedRecordStream{
		backend:       backend,
		recordType:    recordType,
		recordVersion: recordVersion,
		ticker:        time.NewTicker(watchPollInterval),
		changed:       backend.onRecordChange.Bind(),
	}
	stream.ctx, stream.cancel = contextutil.Merge(ctx, backend.closeCtx)
	return stream
}

func (stream *changedRecordStream) Close() error {
	stream.cancel()
	stream.ticker.Stop()
	stream.backend.onRecordChange.Unbind(stream.changed)
	return nil
}

func (stream *changedRecordStream) Next(block bool) bool {
	for {
		if stream.err != nil {
			return false
		}

		var pool *pgxpool.Pool
		_, pool, stream.err = stream.backend.init(stream.ctx)
		if stream.err != nil {
			return false
		}

		stream.record, stream.err = getNextChangedRecord(
			stream.ctx,
			pool,
			stream.recordType,
			stream.recordVersion,
		)
		if isNotFound(stream.err) {
			stream.err = nil
		} else if stream.err != nil {
			return false
		}

		if stream.record != nil {
			stream.recordVersion = stream.record.GetVersion()
			return true
		}

		if !block {
			return false
		}

		select {
		case <-stream.ctx.Done():
			stream.err = stream.ctx.Err()
			return false
		case <-stream.ticker.C:
		case <-stream.changed:
		}
	}
}

func (stream *changedRecordStream) Record() *databroker.Record {
	return stream.record
}

func (stream *changedRecordStream) Err() error {
	return stream.err
}
