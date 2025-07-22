package storage

import (
	"context"
	"errors"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// A RecordStream is a stream of records.
type RecordStream interface {
	// Close closes the record stream and releases any underlying resources.
	Close() error
	// Next is called to retrieve the next record. If one is available it will
	// be returned immediately. If none is available and block is true, the method
	// will block until one is available or an error occurs. The error should be
	// checked with a call to `.Err()`.
	Next(block bool) bool
	// Record returns the current record.
	Record() *databroker.Record
	// Err returns any error that occurred while streaming.
	Err() error
}

// A RecordStreamGenerator generates records for a record stream.
type RecordStreamGenerator = func(ctx context.Context, block bool) (*databroker.Record, error)

type recordStream struct {
	generators []RecordStreamGenerator

	record *databroker.Record
	err    error

	closeCtx context.Context
	close    context.CancelFunc
	onClose  func()
}

// NewRecordStream creates a new RecordStream from a list of generators and an onClose function.
func NewRecordStream(
	ctx context.Context,
	backendClosed <-chan struct{},
	generators []RecordStreamGenerator,
	onClose func(),
) RecordStream {
	stream := &recordStream{
		generators: generators,
		onClose:    onClose,
	}
	stream.closeCtx, stream.close = context.WithCancel(ctx)
	if backendClosed != nil {
		go func() {
			defer stream.close()
			select {
			case <-backendClosed:
			case <-stream.closeCtx.Done():
			}
		}()
	}

	return stream
}

func (stream *recordStream) Close() error {
	stream.close()
	if stream.onClose != nil {
		stream.onClose()
	}
	return nil
}

func (stream *recordStream) Next(block bool) bool {
	for {
		if len(stream.generators) == 0 || stream.err != nil {
			return false
		}

		stream.record, stream.err = stream.generators[0](stream.closeCtx, block)
		if errors.Is(stream.err, ErrStreamDone) {
			stream.err = nil
			stream.generators = stream.generators[1:]
			continue
		}
		break
	}

	return stream.err == nil
}

func (stream *recordStream) Record() *databroker.Record {
	return stream.record
}

func (stream *recordStream) Err() error {
	return stream.err
}

// RecordStreamToList converts a record stream to a list.
func RecordStreamToList(recordStream RecordStream) ([]*databroker.Record, error) {
	var all []*databroker.Record
	for recordStream.Next(false) {
		all = append(all, recordStream.Record())
	}
	return all, recordStream.Err()
}

// RecordListToStream converts a record list to a stream.
func RecordListToStream(ctx context.Context, records []*databroker.Record) RecordStream {
	return NewRecordStream(ctx, nil, []RecordStreamGenerator{
		func(_ context.Context, _ bool) (*databroker.Record, error) {
			if len(records) == 0 {
				return nil, ErrStreamDone
			}

			record := records[0]
			records = records[1:]
			return record, nil
		},
	}, nil)
}

type concatenatedRecordStream struct {
	streams []RecordStream
	index   int
}

// NewConcatenatedRecordStream creates a new record stream that streams all the records from the
// first stream before streaming all the records of the subsequent streams.
func NewConcatenatedRecordStream(streams ...RecordStream) RecordStream {
	return &concatenatedRecordStream{
		streams: streams,
	}
}

func (stream *concatenatedRecordStream) Close() error {
	var err error
	for _, s := range stream.streams {
		if e := s.Close(); e != nil {
			err = e
		}
	}
	return err
}

func (stream *concatenatedRecordStream) Next(block bool) bool {
	for {
		if stream.index >= len(stream.streams) {
			return false
		}

		if stream.streams[stream.index].Next(block) {
			return true
		}

		if stream.streams[stream.index].Err() != nil {
			return false
		}
		stream.index++
	}
}

func (stream *concatenatedRecordStream) Record() *databroker.Record {
	if stream.index >= len(stream.streams) {
		return nil
	}
	return stream.streams[stream.index].Record()
}

func (stream *concatenatedRecordStream) Err() error {
	if stream.index >= len(stream.streams) {
		return nil
	}
	return stream.streams[stream.index].Err()
}
