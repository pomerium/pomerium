package selftests_test

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
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
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
)

func requireOTLPTracesEndpoint(t testing.TB) {
	tracesEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	if tracesEndpoint == "" {
		tracesEndpoint = "http://localhost:4317"
		t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", tracesEndpoint)
	}
	client, err := grpc.NewClient(strings.TrimPrefix(tracesEndpoint, "http://"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	client.Connect()
	ctx, ca := context.WithTimeout(context.Background(), 1*time.Second)
	defer ca()
	if !client.WaitForStateChange(ctx, connectivity.Ready) {
		t.Skip("OTLP server offline: " + tracesEndpoint)
	}
	client.Close()
}

func TestOTLPTracing(t *testing.T) {
	requireOTLPTracesEndpoint(t)
	env := testenv.New(t, testenv.AddTraceDebugFlags(testenv.StandardTraceDebugFlags))
	defer env.Stop()
	up := upstreams.HTTP(nil, upstreams.WithDisplayName("Upstream"))
	up.Handle("/foo", func(w http.ResponseWriter, _ *http.Request) {
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

func TestSampling(t *testing.T) {
	requireOTLPTracesEndpoint(t)
	env := testenv.New(t, testenv.AddTraceDebugFlags(testenv.StandardTraceDebugFlags))
	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		cfg.Options.TracingSampleRate = 0.5
	}))
	defer env.Stop()
	env.Add(scenarios.NewIDP([]*scenarios.User{
		{
			Email:     "foo@example.com",
			FirstName: "Firstname",
			LastName:  "Lastname",
		},
	}))

	up1 := upstreams.HTTP(nil, upstreams.WithNoClientTracing())
	up2 := upstreams.HTTP(nil, upstreams.WithDisplayName("Upstream 2"))
	sampled := atomic.Int32{}
	notSampled := atomic.Int32{}
	handler := func(w http.ResponseWriter, req *http.Request) {
		span := oteltrace.SpanFromContext(req.Context())
		flags := span.SpanContext().TraceFlags()
		if flags.IsSampled() {
			sampled.Add(1)
		} else {
			notSampled.Add(1)
		}
		w.Write([]byte("OK"))
	}
	up1.Handle("/foo", handler)
	up2.Handle("/foo", handler)

	route1 := up1.Route().
		From(env.SubdomainURL("foo")).
		PPL(`{"allow":{"and":["email":{"is":"foo@example.com"}]}}`)

	route2 := up2.Route().
		From(env.SubdomainURL("bar")).
		PPL(`{"allow":{"and":["email":{"is":"foo@example.com"}]}}`)

	env.AddUpstream(up1)
	env.AddUpstream(up2)
	env.Start()
	snippets.WaitStartupComplete(env)

	doRequest := func(ctx context.Context, up upstreams.HTTPUpstream, route testenv.Route) {
		resp, err := up.Get(route, upstreams.AuthenticateAs("foo@example.com"), upstreams.Path("/foo"), upstreams.Context(ctx))
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.NoError(t, resp.Body.Close())
		assert.Equal(t, resp.StatusCode, 200)
		assert.Equal(t, "OK", string(body))
	}

	for range 100 {
		doRequest(context.Background(), up1, route1)
	}

	assert.InDelta(t, int32(50), sampled.Load(), 10)
	assert.InDelta(t, int32(50), notSampled.Load(), 10)

	sampled.Store(0)
	notSampled.Store(0)

	for range 100 {
		doRequest(context.Background(), up2, route2)
	}

	// if the request already has a traceparent header, they will always be sampled
	// regardless of the random sample rate we configured
	assert.InDelta(t, int32(100), sampled.Load(), 10)
	assert.InDelta(t, int32(0), notSampled.Load(), 10)

	sampled.Store(0)
	notSampled.Store(0)

	tracer := trace.NewTracerProvider(env.Context(), "Never Sample", sdktrace.WithSampler(sdktrace.NeverSample())).Tracer(trace.PomeriumCoreTracer)
	for range 100 {
		ctx, span := tracer.Start(context.Background(), "should not sample")
		doRequest(ctx, up2, route2)
		span.End()
	}

	sampled.Store(0)
	notSampled.Store(100)
}
