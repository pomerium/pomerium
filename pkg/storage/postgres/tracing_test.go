package postgres_test

import (
	"context"
	"io"
	"net/http"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/internal/testutil/tracetest"
)

func TestQueryTracing(t *testing.T) {
	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	testutil.WithTestPostgres(t, func(dsn string) {
		receiver := scenarios.NewOTLPTraceReceiver()
		env := testenv.New(t, testenv.WithTraceDebugFlags(testenv.StandardTraceDebugFlags), testenv.WithTraceClient(receiver.NewGRPCClient()))
		env.Add(receiver)

		env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
			cfg.Options.DataBroker.StorageType = config.StoragePostgresName
			cfg.Options.DataBroker.StorageConnectionString = dsn
		}))
		up := upstreams.HTTP(nil, upstreams.WithDisplayName("Upstream"))
		up.Handle("/foo", func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte("OK"))
		})
		env.Add(scenarios.NewIDP([]*scenarios.User{{Email: "user@example.com"}}))

		route := up.Route().
			From(env.SubdomainURL("postgres-test")).
			PPL(`{"allow":{"and":["email":{"is":"user@example.com"}]}}`)
		env.AddUpstream(up)

		env.Start()
		snippets.WaitStartupComplete(env)

		resp, err := up.Get(route, upstreams.AuthenticateAs("user@example.com"), upstreams.Path("/foo"))
		require.NoError(t, err)
		io.ReadAll(resp.Body)
		resp.Body.Close()

		env.Stop()

		results := tracetest.NewTraceResults(receiver.FlushResourceSpans())
		traces, exists := results.GetTraces().ByParticipant["Data Broker"]
		require.True(t, exists)
		var found bool
		for _, trace := range traces {
			for _, span := range trace.Spans {
				if span.Scope.GetName() == "github.com/exaring/otelpgx" {
					found = true
					break
				}
			}
		}
		assert.True(t, found, "no spans with otelpgx scope found")
	})
}
