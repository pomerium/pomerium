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
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/storage/storagetest"
)

func TestBackend(t *testing.T) {
	ctx := t.Context()
	backend := New()
	defer func() { _ = backend.Close() }()
	t.Run("get missing record", func(t *testing.T) {
		record, err := backend.Get(ctx, "TYPE", "abcd")
		require.Error(t, err)
		assert.Nil(t, record)
	})
	t.Run("get record", func(t *testing.T) {
		data := new(anypb.Any)
		sv, err := backend.Put(ctx, []*databroker.Record{
			{
				Type: "TYPE",
				Id:   "a",
				Data: data,
			},
			{
				Type: "TYPE",
				Id:   "b",
				Data: data,
			},
			{
				Type: "TYPE",
				Id:   "c",
				Data: data,
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, backend.serverVersion, sv)
		for i, id := range []string{"a", "b", "c"} {
			record, err := backend.Get(ctx, "TYPE", id)
			require.NoError(t, err)
			if assert.NotNil(t, record) {
				assert.Equal(t, data, record.Data)
				assert.Nil(t, record.DeletedAt)
				assert.Equal(t, id, record.Id)
				assert.NotNil(t, record.ModifiedAt)
				assert.Equal(t, "TYPE", record.Type)
				assert.Equal(t, uint64(i+1), record.Version)
			}
		}
	})
	t.Run("delete record", func(t *testing.T) {
		sv, err := backend.Put(ctx, []*databroker.Record{{
			Type:      "TYPE",
			Id:        "abcd",
			DeletedAt: timestamppb.Now(),
		}})
		assert.NoError(t, err)
		assert.Equal(t, backend.serverVersion, sv)
		record, err := backend.Get(ctx, "TYPE", "abcd")
		assert.Error(t, err)
		assert.Nil(t, record)
	})
	t.Run("patch", func(t *testing.T) {
		storagetest.TestBackendPatch(t, ctx, backend)
	})
}

func TestExpiry(t *testing.T) {
	ctx := t.Context()
	backend := New(WithExpiry(0))
	defer func() { _ = backend.Close() }()

	for i := 0; i < 1000; i++ {
		sv, err := backend.Put(ctx, []*databroker.Record{{
			Type: "TYPE",
			Id:   fmt.Sprint(i),
		}})
		assert.NoError(t, err)
		assert.Equal(t, backend.serverVersion, sv)
	}
	stream, err := backend.Sync(ctx, "", backend.serverVersion, 0)
	require.NoError(t, err)
	var records []*databroker.Record
	for stream.Next(false) {
		records = append(records, stream.Record())
	}
	_ = stream.Close()
	require.Len(t, records, 1000)

	backend.removeChangesBefore(time.Now().Add(time.Second))

	stream, err = backend.Sync(ctx, "", backend.serverVersion, 0)
	require.NoError(t, err)
	records = nil
	for stream.Next(false) {
		records = append(records, stream.Record())
	}
	_ = stream.Close()
	require.Len(t, records, 0)
}

func TestConcurrency(t *testing.T) {
	ctx := t.Context()
	backend := New()

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		for i := 0; i < 1000; i++ {
			_, _ = backend.Get(ctx, "", fmt.Sprint(i))
		}
		return nil
	})
	eg.Go(func() error {
		for i := 0; i < 1000; i++ {
			_, _ = backend.Put(ctx, []*databroker.Record{{
				Id: fmt.Sprint(i),
			}})
		}
		return nil
	})
	assert.NoError(t, eg.Wait())
}

func TestStream(t *testing.T) {
	ctx := t.Context()
	backend := New()
	defer func() { _ = backend.Close() }()

	stream, err := backend.Sync(ctx, "TYPE", backend.serverVersion, 0)
	require.NoError(t, err)
	defer func() { _ = stream.Close() }()

	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		for i := 0; i < 10000; i++ {
			assert.True(t, stream.Next(true))
			assert.Nil(t, stream.Err())
			assert.Equal(t, "TYPE", stream.Record().GetType())
			assert.Equal(t, fmt.Sprint(i), stream.Record().GetId())
			assert.Equal(t, uint64(i+1), stream.Record().GetVersion())
		}
		return nil
	})
	eg.Go(func() error {
		for i := 0; i < 10000; i++ {
			_, err := backend.Put(ctx, []*databroker.Record{{
				Type: "TYPE",
				Id:   fmt.Sprint(i),
			}})
			assert.NoError(t, err)
		}
		return nil
	})
	require.NoError(t, eg.Wait())
}

func TestStreamClose(t *testing.T) {
	ctx := t.Context()
	t.Run("by backend", func(t *testing.T) {
		backend := New()
		stream, err := backend.Sync(ctx, "", backend.serverVersion, 0)
		require.NoError(t, err)
		require.NoError(t, backend.Close())
		assert.False(t, stream.Next(true))
		assert.Error(t, stream.Err())
	})
	t.Run("by stream", func(t *testing.T) {
		backend := New()
		stream, err := backend.Sync(ctx, "", backend.serverVersion, 0)
		require.NoError(t, err)
		require.NoError(t, stream.Close())
		assert.False(t, stream.Next(true))
		assert.Error(t, stream.Err())
	})
	t.Run("by context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(ctx)
		backend := New()
		stream, err := backend.Sync(ctx, "", backend.serverVersion, 0)
		require.NoError(t, err)
		cancel()
		assert.False(t, stream.Next(true))
		assert.Error(t, stream.Err())
	})
}

func TestCapacity(t *testing.T) {
	ctx := t.Context()
	backend := New()
	defer func() { _ = backend.Close() }()

	err := backend.SetOptions(ctx, "EXAMPLE", &databroker.Options{
		Capacity: proto.Uint64(3),
	})
	require.NoError(t, err)

	for i := 0; i < 10; i++ {
		_, err = backend.Put(ctx, []*databroker.Record{{
			Type: "EXAMPLE",
			Id:   fmt.Sprint(i),
		}})
		require.NoError(t, err)
	}

	_, _, stream, err := backend.SyncLatest(ctx, "EXAMPLE", nil)
	require.NoError(t, err)

	records, err := storage.RecordStreamToList(stream)
	require.NoError(t, err)
	assert.Len(t, records, 3)

	var ids []string
	for _, r := range records {
		ids = append(ids, r.GetId())
	}
	assert.Equal(t, []string{"7", "8", "9"}, ids, "should contain recent records")
}

func TestLease(t *testing.T) {
	ctx := t.Context()
	backend := New()
	{
		ok, err := backend.Lease(ctx, "test", "a", time.Second*30)
		require.NoError(t, err)
		assert.True(t, ok, "expected a to acquire the lease")
	}
	{
		ok, err := backend.Lease(ctx, "test", "b", time.Second*30)
		require.NoError(t, err)
		assert.False(t, ok, "expected b to fail to acquire the lease")
	}
	{
		ok, err := backend.Lease(ctx, "test", "a", 0)
		require.NoError(t, err)
		assert.False(t, ok, "expected a to clear the lease")
	}
	{
		ok, err := backend.Lease(ctx, "test", "b", time.Second*30)
		require.NoError(t, err)
		assert.True(t, ok, "expected b to to acquire the lease")
	}
}

// Concurrent calls to Put() and ListTypes() should not cause a data race.
func TestListTypes_concurrent(t *testing.T) {
	ctx := t.Context()
	backend := New()
	for i := 0; i < 10; i++ {
		t := fmt.Sprintf("Type-%02d", i)
		go backend.Put(ctx, []*databroker.Record{{
			Id:   "1",
			Type: t,
		}})
		go backend.ListTypes(ctx)
	}
}
