package inmemory

import (
	"context"
	"sync"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

type recordStream struct {
	ctx     context.Context
	backend *Backend

	changed chan struct{}
	ready   []*databroker.Record
	version uint64

	closeOnce sync.Once
	closed    chan struct{}
}

func newRecordStream(ctx context.Context, backend *Backend, version uint64) *recordStream {
	stream := &recordStream{
		ctx:     ctx,
		backend: backend,

		changed: backend.onChange.Bind(),
		version: version,

		closed: make(chan struct{}),
	}
	return stream
}

func (stream *recordStream) fill() {
	stream.ready = stream.backend.getSince(stream.version)
	if len(stream.ready) > 0 {
		// records are sorted by version,
		// so update the local version to the last record
		stream.version = stream.ready[len(stream.ready)-1].GetVersion()
	}
}

func (stream *recordStream) Close() error {
	stream.closeOnce.Do(func() {
		stream.backend.onChange.Unbind(stream.changed)
		close(stream.closed)
	})
	return nil
}

func (stream *recordStream) Next(wait bool) bool {
	if len(stream.ready) > 0 {
		stream.ready = stream.ready[1:]
	}
	if len(stream.ready) > 0 {
		return true
	}

	for {
		stream.fill()
		if len(stream.ready) > 0 {
			return true
		}

		if wait {
			select {
			case <-stream.ctx.Done():
				return false
			case <-stream.closed:
				return false
			case <-stream.changed:
				// query for records again
			}
		} else {
			return false
		}
	}
}

func (stream *recordStream) Record() *databroker.Record {
	var r *databroker.Record
	if len(stream.ready) > 0 {
		r = stream.ready[0]
	}
	return r
}

func (stream *recordStream) Err() error {
	select {
	case <-stream.ctx.Done():
		return stream.ctx.Err()
	case <-stream.closed:
		return storage.ErrStreamClosed
	case <-stream.backend.closed:
		return storage.ErrStreamClosed
	default:
		return nil
	}
}
