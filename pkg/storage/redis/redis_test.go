package redis

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestChangeSignal(t *testing.T) {
	ctx := context.Background()
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*10)
	defer clearTimeout()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	require.NoError(t, testutil.WithTestRedis(func(rawURL string) error {
		backend1, err := New(rawURL)
		require.NoError(t, err)
		defer func() { _ = backend1.Close() }()

		backend2, err := New(rawURL)
		require.NoError(t, err)
		defer func() { _ = backend2.Close() }()

		ch := backend1.onChange.Bind()
		defer backend1.onChange.Unbind(ch)

		go func() {
			ticker := time.NewTicker(time.Millisecond * 100)
			defer ticker.Stop()
			for {
				_ = backend2.Put(ctx, &databroker.Record{
					Type: "TYPE",
					Id:   "ID",
				})
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()

		select {
		case <-ch:
		case <-ctx.Done():
			t.Fatal("expected signal to be fired when another backend triggers a change")
		}

		return nil
	}))
}

func TestExpiry(t *testing.T) {
	ctx := context.Background()
	require.NoError(t, testutil.WithTestRedis(func(rawURL string) error {
		backend, err := New(rawURL, WithExpiry(0))
		require.NoError(t, err)
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

		return nil
	}))
}
