package postgres

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/storage/storagetest"
)

const maxWait = time.Minute * 10

func TestBackend(t *testing.T) {
	t.Parallel()

	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	ctx, clearTimeout := context.WithTimeout(t.Context(), maxWait)
	defer clearTimeout()

	testutil.WithTestPostgres(t, func(dsn string) {
		backend := New(ctx, dsn)
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
			serverVersion, err := backend.Put(ctx, []*databroker.Record{{
				Type:      "test-1",
				Id:        "r3",
				DeletedAt: timestamppb.Now(),
			}})
			assert.NotEqual(t, 0, serverVersion)
			assert.NoError(t, err)

			stream, err := backend.Sync(ctx, "test-1", serverVersion, 0)
			require.NoError(t, err)
			t.Cleanup(func() { _ = stream.Close() })
			records, err := storage.RecordStreamToList(stream)
			require.NoError(t, err)
			assert.NotEmpty(t, records)
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

		t.Run("unknown type", func(t *testing.T) {
			_, err := backend.pool.Exec(ctx, `
				INSERT INTO `+schemaName+"."+recordsTableName+` (type, id, version, data)
				VALUES ('unknown', '1', 1000, '{"@type":"UNKNOWN","value":{}}')
			`)
			assert.NoError(t, err)

			_, err = backend.Get(ctx, "unknown", "1")
			assert.ErrorIs(t, err, storage.ErrNotFound)

			_, _, stream, err := backend.SyncLatest(ctx, "unknown", nil)
			if assert.NoError(t, err) {
				records, err := storage.RecordStreamToList(stream)
				assert.NoError(t, err)
				assert.Len(t, records, 1)
				stream.Close()
			}
		})

		t.Run("list types", func(t *testing.T) {
			types, err := backend.ListTypes(ctx)
			assert.NoError(t, err)
			assert.Equal(t, []string{"capacity-test", "latest-test", "sync-test", "test-1", "unknown"}, types)
		})

		t.Run("patch", func(t *testing.T) {
			storagetest.TestBackendPatch(t, ctx, backend)
		})

		assert.Equal(t, int32(0), backend.pool.Stat().AcquiredConns(),
			"acquired connections should be released")
	})
}

func TestLookup(t *testing.T) {
	originalDefaultResolver := net.DefaultResolver
	net.DefaultResolver = stubResolver(t)
	t.Cleanup(func() { net.DefaultResolver = originalDefaultResolver })

	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Second*10)
	t.Cleanup(clearTimeout)

	cfg, err := ParseConfig("host=localhost")
	assert.NoError(t, err)

	addrs, err := cfg.ConnConfig.LookupFunc(ctx, "www.example.com")
	assert.NoError(t, err)
	assert.Empty(t, addrs)
}

// stubResolver returns a fake DNS resolver that always responds with NXDOMAIN.
func stubResolver(t *testing.T) *net.Resolver {
	stubListener := bufconn.Listen(1500)
	stubDNS := &dns.Server{
		Listener: stubListener,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := &dns.Msg{}
			m.SetRcode(r, dns.RcodeNameError)
			w.WriteMsg(m)
		}),
	}

	go stubDNS.ActivateAndServe()
	t.Cleanup(func() { stubDNS.Shutdown() })

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return stubListener.DialContext(ctx)
		},
	}
}
