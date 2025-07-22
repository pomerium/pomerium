package postgres

import (
	"context"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/test/bufconn"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/storage/storagetest"
)

func TestBackend(t *testing.T) {
	t.Parallel()

	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	testutil.WithTestPostgres(t, func(dsn string) {
		backend := New(t.Context(), dsn)
		defer backend.Close()

		storagetest.TestBackend(t, backend)

		t.Run("unknown type", func(t *testing.T) {
			_, err := backend.pool.Exec(t.Context(), `
				INSERT INTO `+schemaName+"."+recordsTableName+` (type, id, version, data)
				VALUES ('unknown', '1', 1000, '{"@type":"UNKNOWN","value":{}}')
			`)
			assert.NoError(t, err)

			_, err = backend.Get(t.Context(), "unknown", "1")
			assert.ErrorIs(t, err, storage.ErrNotFound)

			_, _, seq, err := backend.SyncLatest(t.Context(), "unknown", nil)
			if assert.NoError(t, err) {
				records, err := storage.RecordIteratorToList(seq)
				assert.NoError(t, err)
				assert.Len(t, records, 1)
			}
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
