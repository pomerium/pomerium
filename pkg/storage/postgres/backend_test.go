package postgres

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
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

const maxWait = time.Minute * 10

func TestBackend(t *testing.T) {
	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(context.Background(), maxWait)
	defer clearTimeout()

	require.NoError(t, testutil.WithTestPostgres(func(dsn string) error {
		backend := New(dsn)
		defer backend.Close()

		t.Run("put", func(t *testing.T) {
			serverVersion, err := backend.Put(ctx, []*databroker.Record{
				{Type: "test-1", Id: "r1", Data: protoutil.NewAny(protoutil.NewStructMap(map[string]*structpb.Value{
					"k1": protoutil.NewStructString("v1"),
				}))},
				{Type: "test-1", Id: "r2", Data: protoutil.NewAny(protoutil.NewStructMap(map[string]*structpb.Value{
					"k2": protoutil.NewStructString("v2"),
				}))},
			})
			assert.NotEqual(t, 0, serverVersion)
			assert.NoError(t, err)
		})

		t.Run("delete", func(t *testing.T) {
			serverVersion, err := backend.Put(ctx, []*databroker.Record{
				{
					Type: "test-1",
					Id:   "r3",
					Data: protoutil.NewAny(protoutil.NewStructMap(map[string]*structpb.Value{
						"k1": protoutil.NewStructString("v1"),
					})),
					DeletedAt: timestamppb.Now(),
				},
			})
			assert.NotEqual(t, 0, serverVersion)
			assert.NoError(t, err)
		})

		t.Run("capacity", func(t *testing.T) {
			err := backend.SetOptions(ctx, "capacity-test", &databroker.Options{
				Capacity: proto.Uint64(3),
			})
			require.NoError(t, err)

			for i := 0; i < 10; i++ {
				_, err = backend.Put(ctx, []*databroker.Record{{
					Type: "capacity-test",
					Id:   fmt.Sprint(i),
					Data: protoutil.NewAny(protoutil.NewStructMap(map[string]*structpb.Value{})),
				}})
				require.NoError(t, err)
			}

			_, _, stream, err := backend.SyncLatest(ctx, "capacity-test", nil)
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
		})

		t.Run("lease", func(t *testing.T) {
			acquired, err := backend.Lease(ctx, "lease-test", "client-1", time.Second)
			assert.NoError(t, err)
			assert.True(t, acquired)

			acquired, err = backend.Lease(ctx, "lease-test", "client-2", time.Second)
			assert.NoError(t, err)
			assert.False(t, acquired)
		})

		t.Run("latest", func(t *testing.T) {
			for i := 0; i < 100; i++ {
				_, err := backend.Put(ctx, []*databroker.Record{{
					Type: "latest-test",
					Id:   fmt.Sprint(i),
					Data: protoutil.NewAny(protoutil.NewStructMap(map[string]*structpb.Value{})),
				}})
				require.NoError(t, err)
			}

			_, _, stream, err := backend.SyncLatest(ctx, "latest-test", nil)
			require.NoError(t, err)
			defer stream.Close()

			count := map[string]int{}

			for stream.Next(true) {
				count[stream.Record().GetId()]++
			}
			assert.NoError(t, err)

			for i := 0; i < 100; i++ {
				assert.Equal(t, 1, count[fmt.Sprint(i)])
			}
		})

		t.Run("changed", func(t *testing.T) {
			serverVersion, recordVersion, stream, err := backend.SyncLatest(ctx, "sync-test", nil)
			require.NoError(t, err)
			assert.NoError(t, stream.Close())

			stream, err = backend.Sync(ctx, "", serverVersion, recordVersion)
			require.NoError(t, err)
			defer stream.Close()

			go func() {
				for i := 0; i < 10; i++ {
					_, err := backend.Put(ctx, []*databroker.Record{{
						Type: "sync-test",
						Id:   fmt.Sprint(i),
						Data: protoutil.NewAny(protoutil.NewStructMap(map[string]*structpb.Value{})),
					}})
					assert.NoError(t, err)
					time.Sleep(50 * time.Millisecond)
				}
			}()

			for i := 0; i < 10; i++ {
				if assert.True(t, stream.Next(true)) {
					assert.Equal(t, fmt.Sprint(i), stream.Record().GetId())
					assert.Equal(t, "sync-test", stream.Record().GetType())
				} else {
					break
				}
			}
			assert.False(t, stream.Next(false))
			assert.NoError(t, stream.Err())
		})

		return nil
	}))
}

func TestLookup(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	t.Cleanup(clearTimeout)

	cfg, err := ParseConfig("host=localhost")
	assert.NoError(t, err)

	addrs, err := cfg.ConnConfig.LookupFunc(ctx, "test.unknown")
	assert.NoError(t, err)
	assert.Empty(t, addrs)
}
