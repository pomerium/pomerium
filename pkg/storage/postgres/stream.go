package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pomerium/pomerium/pkg/contextutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

const recordBatchSize = 4 * 1024

type recordStream struct {
	backend *Backend
	expr    storage.FilterExpression

	ctx     context.Context
	cancel  context.CancelCauseFunc
	offset  int
	pending []*databroker.Record
	err     error
}

func newRecordStream(
	ctx context.Context,
	backend *Backend,
	expr storage.FilterExpression,
) *recordStream {
	stream := &recordStream{
		backend: backend,
		expr:    expr,
	}
	stream.ctx, stream.cancel = contextutil.Merge(ctx, backend.closeCtx)
	return stream
}

func (stream *recordStream) Close() error {
	stream.cancel(nil)
	return nil
}

func (stream *recordStream) Next(_ bool) bool {
	if stream.err != nil {
		return false
	}

	if len(stream.pending) > 1 {
		stream.pending = stream.pending[1:]
		return true
	}

	var pool *pgxpool.Pool
	_, pool, stream.err = stream.backend.init(stream.ctx)
	if stream.err != nil {
		return false
	}

	stream.pending, stream.err = listRecords(stream.ctx, pool, stream.expr, stream.offset, recordBatchSize)
	if stream.err != nil {
		return false
	}
	stream.offset += recordBatchSize

	return len(stream.pending) > 0
}

func (stream *recordStream) Record() *databroker.Record {
	if len(stream.pending) == 0 {
		return nil
	}
	return stream.pending[0]
}

func (stream *recordStream) Err() error {
	return stream.err
}

const watchPollInterval = 30 * time.Second

type changedRecordStream struct {
	backend       *Backend
	recordType    string
	recordVersion uint64

	ctx     context.Context
	cancel  context.CancelCauseFunc
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
	stream.cancel(nil)
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
