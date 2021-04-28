package inmemory

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestBackend(t *testing.T) {
	ctx := context.Background()
	backend := New()
	defer func() { _ = backend.Close() }()
	t.Run("get missing record", func(t *testing.T) {
		record, err := backend.Get(ctx, "TYPE", "abcd")
		require.Error(t, err)
		assert.Nil(t, record)
	})
	t.Run("get record", func(t *testing.T) {
		data := new(anypb.Any)
		assert.NoError(t, backend.Put(ctx, &databroker.Record{
			Type: "TYPE",
			Id:   "abcd",
			Data: data,
		}))
		record, err := backend.Get(ctx, "TYPE", "abcd")
		require.NoError(t, err)
		if assert.NotNil(t, record) {
			assert.Equal(t, data, record.Data)
			assert.Nil(t, record.DeletedAt)
			assert.Equal(t, "abcd", record.Id)
			assert.NotNil(t, record.ModifiedAt)
			assert.Equal(t, "TYPE", record.Type)
			assert.Equal(t, uint64(1), record.Version)
		}
	})
	t.Run("delete record", func(t *testing.T) {
		assert.NoError(t, backend.Put(ctx, &databroker.Record{
			Type:      "TYPE",
			Id:        "abcd",
			DeletedAt: timestamppb.Now(),
		}))
		record, err := backend.Get(ctx, "TYPE", "abcd")
		assert.Error(t, err)
		assert.Nil(t, record)
	})
	t.Run("get all records", func(t *testing.T) {
		for i := 0; i < 1000; i++ {
			assert.NoError(t, backend.Put(ctx, &databroker.Record{
				Type: "TYPE",
				Id:   fmt.Sprint(i),
			}))
		}
		records, version, err := backend.GetAll(ctx)
		assert.NoError(t, err)
		assert.Len(t, records, 1000)
		assert.Equal(t, uint64(1002), version)
	})
}

func TestExpiry(t *testing.T) {
	ctx := context.Background()
	backend := New(WithExpiry(0))
	defer func() { _ = backend.Close() }()

	for i := 0; i < 1000; i++ {
		assert.NoError(t, backend.Put(ctx, &databroker.Record{
			Type: "TYPE",
			Id:   fmt.Sprint(i),
		}))
	}
	stream, err := backend.Sync(ctx, 0)
	require.NoError(t, err)
	var records []*databroker.Record
	for stream.Next(false) {
		records = append(records, stream.Record())
	}
	_ = stream.Close()
	require.Len(t, records, 1000)

	backend.removeChangesBefore(time.Now().Add(time.Second))

	stream, err = backend.Sync(ctx, 0)
	require.NoError(t, err)
	records = nil
	for stream.Next(false) {
		records = append(records, stream.Record())
	}
	_ = stream.Close()
	require.Len(t, records, 0)
}

func TestConcurrency(t *testing.T) {
	ctx := context.Background()
	backend := New()

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		for i := 0; i < 1000; i++ {
			_, _, _ = backend.GetAll(ctx)
		}
		return nil
	})
	eg.Go(func() error {
		for i := 0; i < 1000; i++ {
			_ = backend.Put(ctx, &databroker.Record{
				Id: fmt.Sprint(i),
			})
		}
		return nil
	})
	assert.NoError(t, eg.Wait())
}

func TestStream(t *testing.T) {
	ctx := context.Background()
	backend := New()
	defer func() { _ = backend.Close() }()

	stream, err := backend.Sync(ctx, 0)
	require.NoError(t, err)
	defer func() { _ = stream.Close() }()

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		for i := 0; i < 10000; i++ {
			assert.True(t, stream.Next(true))
			assert.Equal(t, "TYPE", stream.Record().GetType())
			assert.Equal(t, fmt.Sprint(i), stream.Record().GetId())
			assert.Equal(t, uint64(i+1), stream.Record().GetVersion())
		}
		return nil
	})
	eg.Go(func() error {
		for i := 0; i < 10000; i++ {
			assert.NoError(t, backend.Put(ctx, &databroker.Record{
				Type: "TYPE",
				Id:   fmt.Sprint(i),
			}))
		}
		return nil
	})
	require.NoError(t, eg.Wait())
}

func TestCapacity(t *testing.T) {
	ctx := context.Background()
	backend := New()
	defer func() { _ = backend.Close() }()

	err := backend.SetOptions(ctx, "EXAMPLE", &databroker.Options{
		Capacity: proto.Uint64(3),
	})
	require.NoError(t, err)

	for i := 0; i < 10; i++ {
		err = backend.Put(ctx, &databroker.Record{
			Type: "EXAMPLE",
			Id:   fmt.Sprint(i),
		})
		require.NoError(t, err)
	}

	records, _, err := backend.GetAll(ctx)
	require.NoError(t, err)
	assert.Len(t, records, 3)

	var ids []string
	for _, r := range records {
		ids = append(ids, r.GetId())
	}
	assert.Equal(t, []string{"7", "8", "9"}, ids, "should contain recent records")
}
