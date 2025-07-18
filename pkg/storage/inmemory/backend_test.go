package inmemory

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage/storagetest"
)

func TestBackend(t *testing.T) {
	t.Parallel()

	backend := New()
	t.Cleanup(func() { backend.Close() })

	storagetest.TestBackend(t, backend)
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
