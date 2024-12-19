package selftests_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

func otlpTraceReceiverOrFromEnv(t *testing.T) (modifier testenv.Modifier, newRemoteClient func() otlptrace.Client, getResults func() *testutil.TraceResults) {
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	tracesEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	if tracesEndpoint == "" {
		tracesEndpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		if tracesEndpoint == "" {
			srv := scenarios.NewOTLPTraceReceiver()
			return srv, srv.NewClient, func() *testutil.TraceResults {
				return testutil.NewTraceResults(srv.FlushResourceSpans())
			}
		}
	}
	return testenv.NoopModifier(), trace.NewRemoteClientFromEnv, nil
}

var allServices = []string{
	"Test Environment",
	"Authorize",
	"Authenticate",
	"Control Plane",
	"Data Broker",
	"Upstream",
	"IDP",
	"HTTP Client",
	"Envoy",
}

func TestOTLPTracing(t *testing.T) {
	modifier, newRemoteClient, getResults := otlpTraceReceiverOrFromEnv(t)
	env := testenv.New(t, testenv.WithTraceDebugFlags(testenv.StandardTraceDebugFlags), testenv.WithTraceClient(newRemoteClient()))
	env.Add(modifier)

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
	resp, err := up.Get(route, upstreams.AuthenticateAs("foo@example.com"), upstreams.Path("/foo"), upstreams.Context(ctx))
	span.End()
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.NoError(t, resp.Body.Close())
	assert.Equal(t, resp.StatusCode, 200)
	assert.Equal(t, "OK", string(body))

	env.Stop()

	if getResults != nil {
		results := getResults()
		var (
			testEnvironmentLocalTest    = fmt.Sprintf("Test Environment: %s", t.Name())
			testEnvironmentAuthenticate = "Test Environment: Authenticate"
			authenticateOAuth2Client    = "Authenticate: OAuth2 Client: GET /.well-known/jwks.json"
			idpServerGetUserinfo        = "IDP: Server: GET /oidc/userinfo"
			idpServerPostToken          = "IDP: Server: POST /oidc/token"
			controlPlaneEnvoyAccessLogs = "Control Plane: envoy.service.accesslog.v3.AccessLogService/StreamAccessLogs"
			controlPlaneEnvoyDiscovery  = "Control Plane: envoy.service.discovery.v3.AggregatedDiscoveryService/DeltaAggregatedResources"
			controlPlaneExport          = "Control Plane: opentelemetry.proto.collector.trace.v1.TraceService/Export"
		)

		results.MatchTraces(t,
			testutil.MatchOptions{
				Exact:              true,
				CheckDetachedSpans: true,
			},
			testutil.Match{Name: testEnvironmentLocalTest, TraceCount: 1, Services: []string{"Test Environment", "Control Plane", "Data Broker"}},
			testutil.Match{Name: testEnvironmentAuthenticate, TraceCount: 1, Services: allServices},
			testutil.Match{Name: authenticateOAuth2Client, TraceCount: testutil.Greater(0)},
			testutil.Match{Name: idpServerGetUserinfo, TraceCount: testutil.SameAs(authenticateOAuth2Client)},
			testutil.Match{Name: idpServerPostToken, TraceCount: testutil.SameAs(authenticateOAuth2Client)},
			testutil.Match{Name: controlPlaneEnvoyDiscovery, TraceCount: 1},
			testutil.Match{Name: controlPlaneExport, TraceCount: testutil.Greater(0)},
			testutil.Match{Name: controlPlaneEnvoyAccessLogs, TraceCount: testutil.Any{}},
		)
	}
}

func TestSampling(t *testing.T) {
	modifier, newRemoteClient, getResults := otlpTraceReceiverOrFromEnv(t)
	env := testenv.New(t, testenv.WithTraceDebugFlags(testenv.StandardTraceDebugFlags), testenv.WithTraceClient(newRemoteClient()))
	env.Add(modifier)

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		cfg.Options.TracingSampleRate = 0.5
	}))
	env.Add(scenarios.NewIDP([]*scenarios.User{
		{
			Email:     "foo@example.com",
			FirstName: "Firstname",
			LastName:  "Lastname",
		},
	}))

	upstreamNoClientTracing := upstreams.HTTP(nil, upstreams.WithNoClientTracing(), upstreams.WithDisplayName("Upstream"))
	sampled := map[string]*atomic.Int32{}
	notSampled := map[string]*atomic.Int32{}
	readSampled := func(t testing.TB) int32 {
		return sampled["/"+t.Name()].Load()
	}
	readNotSampled := func(t testing.TB) int32 {
		return notSampled["/"+t.Name()].Load()
	}
	var mu sync.Mutex
	setupCounters := func(t testing.TB) {
		mu.Lock()
		defer mu.Unlock()
		sampled["/"+t.Name()] = &atomic.Int32{}
		notSampled["/"+t.Name()] = &atomic.Int32{}
	}

	handler := func(w http.ResponseWriter, req *http.Request) {
		span := oteltrace.SpanFromContext(req.Context())
		spanId := span.SpanContext().SpanID().String()
		traceId := span.SpanContext().TraceID().String()
		_, _ = spanId, traceId
		flags := span.SpanContext().TraceFlags()
		path := req.URL.Path
		if flags.IsSampled() {
			sampled[path].Add(1)
		} else {
			notSampled[path].Add(1)
		}
		w.Write([]byte("OK"))
	}
	upstreamNoClientTracing.Handle(fmt.Sprintf("/%s/{name}", t.Name()), handler)

	route1 := upstreamNoClientTracing.Route().
		From(env.SubdomainURL("sampling-50pct")).
		PPL(`{"allow":{"and":["email":{"is":"foo@example.com"}]}}`)

	env.AddUpstream(upstreamNoClientTracing)
	env.Start()
	snippets.WaitStartupComplete(env)

	doRequest := func(t testing.TB, ctx context.Context, up upstreams.HTTPUpstream, route testenv.Route) {
		resp, err := up.Get(route, upstreams.AuthenticateAs("foo@example.com"), upstreams.Path(t.Name()), upstreams.Context(ctx))
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.NoError(t, resp.Body.Close())
		assert.Equal(t, resp.StatusCode, 200)
		assert.Equal(t, "OK", string(body))
	}

	t.Run("no-external-traceparent", func(t *testing.T) {
		setupCounters(t)
		for {
			doRequest(t, context.Background(), upstreamNoClientTracing, route1)
			if readSampled(t) == 10 {
				break
			}
		}

		assert.Equal(t, int32(10), readSampled(t))         // 10 sampled
		assert.InDelta(t, int32(10), readNotSampled(t), 5) // between 5-15 unsampled

		if getResults != nil {
			results := getResults()
			results.MatchTraces(t, testutil.MatchOptions{Exact: false, CheckDetachedSpans: true}, testutil.Match{}) // testutil.Match{Name: }

		}
	})

	t.Run("external-traceparent-always-sample", func(t *testing.T) {
		setupCounters(t)
		tracer := trace.NewTracerProvider(env.Context(), "Always Sample", sdktrace.WithSampler(sdktrace.AlwaysSample())).Tracer(trace.PomeriumCoreTracer)
		for range 100 {
			ctx, span := tracer.Start(context.Background(), "should sample")
			doRequest(t, ctx, upstreamNoClientTracing, route1)
			span.End()
		}

		// if the request already has a traceparent header, they will always be sampled
		// regardless of the random sample rate we configured
		assert.Equal(t, int32(100), readSampled(t))
		assert.Equal(t, int32(0), readNotSampled(t))
	})

	t.Run("external-traceparent-never-sample", func(t *testing.T) {
		setupCounters(t)
		tracer := trace.NewTracerProvider(env.Context(), "Never Sample", sdktrace.WithSampler(sdktrace.NeverSample())).Tracer(trace.PomeriumCoreTracer)
		for range 100 {
			ctx, span := tracer.Start(context.Background(), "should not sample")
			doRequest(t, ctx, upstreamNoClientTracing, route1)
			span.End()
		}

		assert.Equal(t, int32(0), readSampled(t))
		assert.Equal(t, int32(100), readNotSampled(t))
	})

	env.Stop()
}

func TestExternalSpans(t *testing.T) {
	modifier, newRemoteClient, getResults := otlpTraceReceiverOrFromEnv(t)

	// set up external tracer
	external := otlptrace.NewUnstarted(newRemoteClient())
	r, err := resource.Merge(
		resource.Empty(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("External"),
		),
	)
	require.NoError(t, err)

	externalTracerProvider := sdktrace.NewTracerProvider(sdktrace.WithBatcher(external), sdktrace.WithResource(r))

	env := testenv.New(t, testenv.WithTraceDebugFlags(testenv.StandardTraceDebugFlags), testenv.WithTraceClient(newRemoteClient()))
	env.Add(modifier)

	up := upstreams.HTTP(nil, upstreams.WithNoClientTracing())
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
	require.NoError(t, external.Start(env.Context()))
	snippets.WaitStartupComplete(env)

	ctx, span := externalTracerProvider.Tracer("external").Start(context.Background(), "External Root", oteltrace.WithNewRoot())
	t.Logf("external span id: %s", span.SpanContext().SpanID().String())
	resp, err := up.Get(route, upstreams.AuthenticateAs("foo@example.com"), upstreams.Path("/foo"), upstreams.Context(ctx))
	span.End()
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.NoError(t, resp.Body.Close())
	assert.Equal(t, resp.StatusCode, 200)
	assert.Equal(t, "OK", string(body))

	assert.NoError(t, externalTracerProvider.ForceFlush(context.Background()))
	assert.NoError(t, externalTracerProvider.Shutdown(context.Background()))
	external.Shutdown(ctx)
	env.Stop()

	if getResults != nil {
		// results := getResults()
		// resources := []*resourcev1.Resource{}
		// for _, res := range results {
		// 	resources = append(resources, res.Resource)
		// }
		// assertResourceNamesPresent(t, resources, commonResourceNames)

		// results := getResults()
		// traces := results.GetTraces()
		// assert.Len(t, traces, 1)
	}
}
