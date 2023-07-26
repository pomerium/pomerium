package redis

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestBackend(t *testing.T) {
	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	handler := func(t *testing.T, useTLS bool, rawURL string) error {
		ctx := context.Background()
		var opts []Option
		if useTLS {
			opts = append(opts, WithTLSConfig(testutil.RedisTLSConfig()))
		}
		backend, err := New(rawURL, opts...)
		require.NoError(t, err)
		defer func() { _ = backend.Close() }()

		serverVersion, err := backend.getOrCreateServerVersion(ctx)
		require.NoError(t, err)

		t.Run("get missing record", func(t *testing.T) {
			record, err := backend.Get(ctx, "TYPE", "abcd")
			require.Error(t, err)
			assert.Nil(t, record)
		})
		t.Run("get record", func(t *testing.T) {
			data := new(anypb.Any)
			sv, err := backend.Put(ctx, []*databroker.Record{{
				Type: "TYPE",
				Id:   "abcd",
				Data: data,
			}})
			assert.NoError(t, err)
			assert.Equal(t, serverVersion, sv)
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
			sv, err := backend.Put(ctx, []*databroker.Record{{
				Type:      "TYPE",
				Id:        "abcd",
				DeletedAt: timestamppb.Now(),
			}})
			assert.NoError(t, err)
			assert.Equal(t, serverVersion, sv)
			record, err := backend.Get(ctx, "TYPE", "abcd")
			assert.Error(t, err)
			assert.Nil(t, record)
		})
		t.Run("list types", func(t *testing.T) {
			types, err := backend.ListTypes(ctx)
			assert.NoError(t, err)
			assert.Equal(t, []string{"TYPE"}, types)
		})
		return nil
	}

	t.Run("no-tls", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, testutil.WithTestRedis(false, func(rawURL string) error {
			return handler(t, false, rawURL)
		}))
	})

	t.Run("tls", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, testutil.WithTestRedis(true, func(rawURL string) error {
			return handler(t, true, rawURL)
		}))
	})

	if runtime.GOOS == "linux" {
		t.Run("cluster", func(t *testing.T) {
			t.Parallel()
			require.NoError(t, testutil.WithTestRedisCluster(func(rawURL string) error {
				return handler(t, false, rawURL)
			}))
		})

		t.Run("sentinel", func(t *testing.T) {
			t.Parallel()
			require.NoError(t, testutil.WithTestRedisSentinel(func(rawURL string) error {
				return handler(t, false, rawURL)
			}))
		})
	}
}

func TestChangeSignal(t *testing.T) {
	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	t.Parallel()

	ctx := context.Background()
	require.NoError(t, testutil.WithTestRedis(false, func(rawURL string) error {
		ctx, clearTimeout := context.WithTimeout(ctx, time.Second*30)
		defer clearTimeout()

		done := make(chan struct{})
		var eg errgroup.Group
		eg.Go(func() error {
			backend, err := New(rawURL)
			if err != nil {
				return err
			}
			defer func() { _ = backend.Close() }()

			ch := backend.onChange.Bind()
			defer backend.onChange.Unbind(ch)

			select {
			case <-ch:
			case <-ctx.Done():
				return ctx.Err()
			}

			// signal the second backend that we've received the change
			close(done)

			return nil
		})
		eg.Go(func() error {
			backend, err := New(rawURL)
			if err != nil {
				return err
			}
			defer func() { _ = backend.Close() }()

			// put a new value to trigger a change
			for {
				_, err = backend.Put(ctx, []*databroker.Record{{
					Type: "TYPE",
					Id:   "ID",
				}})
				if err != nil {
					return err
				}

				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-done:
					return nil
				case <-time.After(time.Millisecond * 100):
				}
			}
		})
		assert.NoError(t, eg.Wait(), "expected signal to be fired when another backend triggers a change")
		return nil
	}))
}

func TestExpiry(t *testing.T) {
	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	t.Parallel()

	ctx := context.Background()
	require.NoError(t, testutil.WithTestRedis(false, func(rawURL string) error {
		backend, err := New(rawURL, WithExpiry(0))
		require.NoError(t, err)
		defer func() { _ = backend.Close() }()

		serverVersion, err := backend.getOrCreateServerVersion(ctx)
		require.NoError(t, err)

		for i := 0; i < 1000; i++ {
			_, err := backend.Put(ctx, []*databroker.Record{{
				Type: "TYPE",
				Id:   fmt.Sprint(i),
			}})
			assert.NoError(t, err)
		}
		stream, err := backend.Sync(ctx, "TYPE", serverVersion, 0)
		require.NoError(t, err)
		var records []*databroker.Record
		for stream.Next(false) {
			records = append(records, stream.Record())
		}
		_ = stream.Close()
		require.Len(t, records, 1000)

		backend.removeChangesBefore(ctx, time.Now().Add(time.Second))

		stream, err = backend.Sync(ctx, "TYPE", serverVersion, 0)
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

func TestCapacity(t *testing.T) {
	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	defer clearTimeout()

	require.NoError(t, testutil.WithTestRedis(false, func(rawURL string) error {
		backend, err := New(rawURL, WithExpiry(0))
		require.NoError(t, err)
		defer func() { _ = backend.Close() }()

		err = backend.SetOptions(ctx, "EXAMPLE", &databroker.Options{
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
		defer stream.Close()

		records, err := storage.RecordStreamToList(stream)
		require.NoError(t, err)
		assert.Len(t, records, 3)

		var ids []string
		for _, r := range records {
			ids = append(ids, r.GetId())
		}
		assert.Equal(t, []string{"7", "8", "9"}, ids, "should contain recent records")

		return nil
	}))
}

func TestLease(t *testing.T) {
	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	t.Parallel()

	ctx := context.Background()
	require.NoError(t, testutil.WithTestRedis(false, func(rawURL string) error {
		backend, err := New(rawURL)
		require.NoError(t, err)
		defer func() { _ = backend.Close() }()

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

		return nil
	}))
}
