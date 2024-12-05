package selftests_test

import (
	"context"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

func TestOTLPTracing(t *testing.T) {
	tracesEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	if tracesEndpoint == "" {
		tracesEndpoint = "http://localhost:4317"
		os.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", tracesEndpoint)
	}
	client, err := grpc.NewClient(tracesEndpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	client.Connect()
	ctx, ca := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer ca()
	if !client.WaitForStateChange(ctx, connectivity.Ready) {
		t.Skip("OTLP server offline: " + tracesEndpoint)
	}
	client.Close()

	env := testenv.New(t, testenv.AddTraceDebugFlags(
		trace.WarnOnIncompleteSpans|
			trace.WarnOnIncompleteTraces|
			trace.WarnOnUnresolvedReferences|
			trace.LogTraceIDMappingsOnWarn|
			trace.LogAllSpansOnWarn,
	))
	defer env.Stop()
	env.Add(testenv.ModifierFunc(func(ctx context.Context, cfg *config.Config) {
		cfg.Options.ProxyLogLevel = config.LogLevelInfo
	}))
	up := upstreams.HTTP(nil, upstreams.WithDisplayName("Upstream"))
	up.Handle("/foo", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("OK"))
	})
	env.Add(scenarios.NewIDP([]*scenarios.User{
		{
			Email:     "foo@example.com",
			FirstName: "Firstname",
			LastName:  "Lastname",
		},
	}))

	route := up.Route().
		From(env.SubdomainURL("foo")).
		PPL(`{"allow":{"and":["email":{"is":"foo@example.com"}]}}`)

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	ctx, span := env.Tracer().Start(env.Context(), "Authenticate", oteltrace.WithNewRoot())
	defer span.End()
	resp, err := up.Get(route, upstreams.AuthenticateAs("foo@example.com"), upstreams.Path("/foo"), upstreams.Context(ctx))
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.NoError(t, resp.Body.Close())
	assert.Equal(t, resp.StatusCode, 200)
	assert.Equal(t, "OK", string(body))
}
