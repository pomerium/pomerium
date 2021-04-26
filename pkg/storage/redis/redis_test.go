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
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
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
				require.NoError(t, backend.Put(ctx, &databroker.Record{
					Type: "TYPE",
					Id:   fmt.Sprint(i),
				}))
			}
			records, version, err := backend.GetAll(ctx)
			assert.NoError(t, err)
			assert.Len(t, records, 1000)
			assert.Equal(t, uint64(1002), version)
		})
		return nil
	}

	t.Run("no-tls", func(t *testing.T) {
		require.NoError(t, testutil.WithTestRedis(false, func(rawURL string) error {
			return handler(t, false, rawURL)
		}))
	})

	t.Run("tls", func(t *testing.T) {
		require.NoError(t, testutil.WithTestRedis(true, func(rawURL string) error {
			return handler(t, true, rawURL)
		}))
	})

	if runtime.GOOS == "linux" {
		t.Run("cluster", func(t *testing.T) {
			require.NoError(t, testutil.WithTestRedisCluster(func(rawURL string) error {
				return handler(t, false, rawURL)
			}))
		})

		t.Run("sentinel", func(t *testing.T) {
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

	ctx := context.Background()
	ctx, clearTimeout := context.WithTimeout(ctx, time.Second*10)
	defer clearTimeout()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	require.NoError(t, testutil.WithTestRedis(false, func(rawURL string) error {
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
	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	ctx := context.Background()
	require.NoError(t, testutil.WithTestRedis(false, func(rawURL string) error {
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

		backend.removeChangesBefore(ctx, time.Now().Add(time.Second))

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

func TestCapacity(t *testing.T) {
	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	ctx := context.Background()
	require.NoError(t, testutil.WithTestRedis(false, func(rawURL string) error {
		backend, err := New(rawURL, WithExpiry(0))
		require.NoError(t, err)
		defer func() { _ = backend.Close() }()

		err = backend.SetOptions(ctx, "EXAMPLE", &databroker.Options{
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

		return nil
	}))
}
