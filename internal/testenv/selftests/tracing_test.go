package selftests_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"testing"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	oteltrace "go.opentelemetry.io/otel/trace"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func otlpTraceReceiverOrFromEnv(t *testing.T) (modifier testenv.Modifier, remoteClient otlptrace.Client, getResults func() []*tracev1.ResourceSpans) {
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	tracesEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	if tracesEndpoint == "" {
		tracesEndpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		if tracesEndpoint == "" {
			srv := scenarios.NewOTLPTraceReceiver()
			return srv, srv.NewClient(), srv.ResourceSpans
		}
	}
	return testenv.NoopModifier(), trace.NewRemoteClientFromEnv(), func() []*tracev1.ResourceSpans { return nil }
}

func TestOTLPTracing(t *testing.T) {
	modifier, remoteClient, getResults := otlpTraceReceiverOrFromEnv(t)
	env := testenv.New(t, testenv.WithTraceDebugFlags(testenv.StandardTraceDebugFlags), testenv.WithTraceClient(remoteClient))
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

	results := getResults()
	resources := []*resourcev1.Resource{}
	for _, res := range results {
		resources = append(resources, res.Resource)
	}

	for _, res := range resources {
		jsondata := protojson.Format(res)
		fmt.Println(string(jsondata))
	}
	assert.NotEmpty(t, results)
	for _, service := range []string{
		"Test Environment",
		"Authorize",
		"Authenticate",
		"Control Plane",
		"Data Broker",
		"Upstream",
		"IDP",
		"HTTP Client",
	} {
		assertResourceExists(t, resources, attribute.NewSet(
			attribute.String("service.name", service),
			attribute.String("telemetry.sdk.language", "go"),
			attribute.String("telemetry.sdk.name", "opentelemetry"),
		))
	}
	assertResourceExists(t, resources, attribute.NewSet(
		attribute.String("service.name", "Envoy"),
		attribute.String("pomerium.envoy", "true"),
	))
}

func assertResourceExists(t *testing.T, resources []*resourcev1.Resource, attrs attribute.Set) {
	for _, res := range resources {
		set := trace.NewAttributeSet(res.Attributes...)
		set, _ = set.Filter(func(kv attribute.KeyValue) bool {
			return attrs.HasValue(kv.Key)
		})
		if set.Equals(&attrs) {
			return
		}
	}
	t.Error("resource not found")
}

func TestSampling(t *testing.T) {
	modifier, remoteClient, _ := otlpTraceReceiverOrFromEnv(t)
	env := testenv.New(t, testenv.WithTraceDebugFlags(testenv.StandardTraceDebugFlags), testenv.WithTraceClient(remoteClient))
	env.Add(modifier)

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
	assert.Equal(t, int32(100), sampled.Load())
	assert.Equal(t, int32(0), notSampled.Load())

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

func TestExternalSpans(t *testing.T) {
	modifier, remoteClient, _ := otlpTraceReceiverOrFromEnv(t)

	// set up external tracer
	external, err := otlptrace.New(context.Background(), remoteClient)
	require.NoError(t, err)
	r, err := resource.Merge(
		resource.Empty(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("External"),
		),
	)
	require.NoError(t, err)

	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(external), sdktrace.WithResource(r))

	env := testenv.New(t, testenv.WithTraceDebugFlags(testenv.StandardTraceDebugFlags), testenv.WithTraceClient(remoteClient))
	env.Add(modifier)

	defer env.Stop()
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

	snippets.WaitStartupComplete(env)

	ctx, span := tp.Tracer("external").Start(context.Background(), "External Root", oteltrace.WithNewRoot())
	t.Logf("external span id: %s", span.SpanContext().SpanID().String())
	resp, err := up.Get(route, upstreams.AuthenticateAs("foo@example.com"), upstreams.Path("/foo"), upstreams.Context(ctx))
	span.End()
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.NoError(t, resp.Body.Close())
	assert.Equal(t, resp.StatusCode, 200)
	assert.Equal(t, "OK", string(body))

	assert.NoError(t, tp.ForceFlush(context.Background()))
	assert.NoError(t, tp.Shutdown(context.Background()))
	external.Shutdown(ctx)
}
