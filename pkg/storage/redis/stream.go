package redis

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang/protobuf/proto"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type recordStream struct {
	ctx     context.Context
	backend *Backend

	changed chan struct{}
	version uint64
	record  *databroker.Record
	err     error

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
	// if the backend is closed, close the stream
	go func() {
		select {
		case <-stream.closed:
		case <-backend.closed:
			_ = stream.Close()
		}
	}()
	return stream
}

func (stream *recordStream) Close() error {
	stream.closeOnce.Do(func() {
		stream.backend.onChange.Unbind(stream.changed)
		close(stream.closed)
	})
	return nil
}

func (stream *recordStream) Next(block bool) bool {
	if stream.err != nil {
		return false
	}

	ticker := time.NewTicker(watchPollInterval)
	defer ticker.Stop()

	for {
		cmd := stream.backend.client.ZRangeByScore(stream.ctx, changesSetKey, &redis.ZRangeBy{
			Min:    fmt.Sprintf("(%d", stream.version),
			Max:    "+inf",
			Offset: 0,
			Count:  1,
		})
		results, err := cmd.Result()
		if err != nil {
			stream.err = err
			return false
		}

		if len(results) > 0 {
			result := results[0]
			var record databroker.Record
			err = proto.Unmarshal([]byte(result), &record)
			if err != nil {
				log.Warn().Err(err).Msg("redis: invalid record detected")
			} else {
				stream.record = &record
			}
			stream.version++
			return true
		}

		if block {
			select {
			case <-stream.ctx.Done():
				stream.err = stream.ctx.Err()
				return false
			case <-stream.closed:
				return false
			case <-ticker.C: // check again
			case <-stream.changed: // check again
			}
		} else {
			return false
		}
	}
}

func (stream *recordStream) Record() *databroker.Record {
	return stream.record
}

func (stream *recordStream) Err() error {
	return stream.err
}
