package selftests_test

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	. "github.com/pomerium/pomerium/internal/testutil/tracetest" //nolint:revive
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

func otlpTraceReceiverOrFromEnv(t *testing.T) (modifier testenv.Modifier, newRemoteClient func() otlptrace.Client, getResults func() *TraceResults) {
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	tracesEndpoint := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	if tracesEndpoint == "" {
		tracesEndpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		if tracesEndpoint == "" {
			srv := scenarios.NewOTLPTraceReceiver()
			return srv,
				func() otlptrace.Client {
					return srv.NewGRPCClient()
				},
				func() *TraceResults {
					return NewTraceResults(srv.FlushResourceSpans())
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
	"Proxy",
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
			MatchOptions{
				Exact:              true,
				CheckDetachedSpans: true,
			},
			Match{Name: testEnvironmentLocalTest, TraceCount: 1, Services: []string{"Test Environment", "Control Plane", "Data Broker"}},
			Match{Name: testEnvironmentAuthenticate, TraceCount: 1, Services: allServices},
			Match{Name: authenticateOAuth2Client, TraceCount: Greater(0)},
			Match{Name: idpServerGetUserinfo, TraceCount: EqualToMatch(authenticateOAuth2Client)},
			Match{Name: idpServerPostToken, TraceCount: EqualToMatch(authenticateOAuth2Client)},
			Match{Name: controlPlaneEnvoyDiscovery, TraceCount: 1},
			Match{Name: controlPlaneExport, TraceCount: Greater(0)},
			Match{Name: controlPlaneEnvoyAccessLogs, TraceCount: Any{}},
		)
	}
}

func TestOTLPTracing_TraceCorrelation(t *testing.T) {
	modifier, newRemoteClient, getResults := otlpTraceReceiverOrFromEnv(t)
	env := testenv.New(t, testenv.WithTraceDebugFlags(testenv.StandardTraceDebugFlags), testenv.WithTraceClient(newRemoteClient()))
	env.Add(modifier)

	up := upstreams.HTTP(nil, upstreams.WithDisplayName("Upstream"), upstreams.WithNoClientTracing())
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

	resp, err := up.Get(route, upstreams.AuthenticateAs("foo@example.com"), upstreams.Path("/foo"), upstreams.Context(context.Background()))
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.NoError(t, resp.Body.Close())
	assert.Equal(t, resp.StatusCode, 200)
	assert.Equal(t, "OK", string(body))

	env.Stop()
	if getResults != nil {
		results := getResults()
		traces := results.GetTraces()
		// one unauthenticated (ends in /.pomerium/callback redirect), one authenticated
		assert.Len(t, traces.ByName[fmt.Sprintf("Envoy: ingress: GET foo.localhost.pomerium.io:%d/foo", env.Ports().ProxyHTTP.Value())].WithoutErrors(), 2)
	}
}

type SamplingTestSuite struct {
	suite.Suite
	env        testenv.Environment
	getResults func() *TraceResults
	route      testenv.Route
	upstream   upstreams.HTTPUpstream

	sampled    atomic.Int32
	notSampled atomic.Int32
}

func (s *SamplingTestSuite) SetupTest() {
	modifier, newRemoteClient, getResults := otlpTraceReceiverOrFromEnv(s.T())
	s.getResults = getResults
	s.env = testenv.New(s.T(),
		testenv.WithTraceDebugFlags(testenv.StandardTraceDebugFlags|trace.EnvoyFlushEverySpan),
		testenv.WithTraceClient(newRemoteClient()),
	)
	s.env.Add(modifier)

	s.sampled.Store(0)
	s.notSampled.Store(0)

	s.env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		half := 0.5
		cfg.Options.TracingSampleRate = &half
	}))
	s.env.Add(scenarios.NewIDP([]*scenarios.User{
		{
			Email:     "foo@example.com",
			FirstName: "Firstname",
			LastName:  "Lastname",
		},
	}))

	s.upstream = upstreams.HTTP(nil, upstreams.WithNoClientTracing(), upstreams.WithDisplayName("Upstream"))
	s.upstream.Handle("/", s.handleRequest)

	s.route = s.upstream.Route().
		From(s.env.SubdomainURL("sampling-50pct")).
		PPL(`{"allow":{"and":["email":{"is":"foo@example.com"}]}}`)

	s.env.AddUpstream(s.upstream)
	s.env.Start()
	snippets.WaitStartupComplete(s.env)
}

func (s *SamplingTestSuite) TearDownTest() {
	s.env.Stop()
}

func (s *SamplingTestSuite) handleRequest(w http.ResponseWriter, req *http.Request) {
	span := oteltrace.SpanFromContext(req.Context())
	flags := span.SpanContext().TraceFlags()
	if flags.IsSampled() {
		s.sampled.Add(1)
	} else {
		s.notSampled.Add(1)
	}
	w.Write([]byte("OK"))
}

func (s *SamplingTestSuite) doRequest(ctx context.Context) {
	resp, err := s.upstream.Get(s.route, upstreams.AuthenticateAs("foo@example.com"), upstreams.Path("/"), upstreams.Context(ctx))
	s.Require().NoError(err)
	body, err := io.ReadAll(resp.Body)
	s.Assert().NoError(err)
	s.Assert().NoError(resp.Body.Close())
	s.Assert().Equal(resp.StatusCode, 200)
	s.Assert().Equal("OK", string(body))
}

func (s *SamplingTestSuite) TestNoExternalTraceparent() {
	for {
		s.doRequest(context.Background())
		if s.sampled.Load() == 20 {
			break
		}
	}

	s.Assert().NoError(trace.ForceFlush(s.env.Context()))
	trace.WaitForSpans(s.env.Context(), 10*time.Second)

	s.Assert().Equal(int32(20), s.sampled.Load()) // 10 sampled
	// Ideally we get ~50% sample rate, but CI will always be unlucky.
	s.Assert().Greater(s.notSampled.Load(), int32(0))

	if s.getResults != nil {
		results := s.getResults()
		traces := results.GetTraces()
		s.Assert().Len(traces.ByParticipant["Upstream"], 20)
	}
}

func (s *SamplingTestSuite) TestExternalTraceparentAlwaysSample() {
	tracer := trace.NewTracerProvider(s.env.Context(), "Always Sample",
		sdktrace.WithSampler(sdktrace.AlwaysSample())).Tracer(trace.PomeriumCoreTracer)
	for range 100 {
		ctx, span := tracer.Start(context.Background(), "should sample")
		s.doRequest(ctx)
		span.End()
	}

	s.Assert().NoError(trace.ForceFlush(s.env.Context()))
	trace.WaitForSpans(s.env.Context(), 10*time.Second)

	// if the request already has a traceparent header, they will always be sampled
	// regardless of the random sample rate we configured
	s.Assert().Equal(int32(100), s.sampled.Load())
	s.Assert().Equal(int32(0), s.notSampled.Load())

	if s.getResults != nil {
		results := s.getResults()
		traces := results.GetTraces()
		s.Assert().Len(traces.ByParticipant["Envoy"], 100)
	}
}

func (s *SamplingTestSuite) TestExternalTraceparentNeverSample() {
	tracer := trace.NewTracerProvider(s.env.Context(), "Never Sample", sdktrace.WithSampler(sdktrace.NeverSample())).Tracer(trace.PomeriumCoreTracer)
	for range 100 {
		ctx, span := tracer.Start(context.Background(), "should not sample")
		s.doRequest(ctx)
		span.End()
	}

	s.Assert().NoError(trace.ForceFlush(s.env.Context()))
	trace.WaitForSpans(s.env.Context(), 10*time.Second)

	s.Assert().Equal(int32(0), s.sampled.Load())
	s.Assert().Equal(int32(100), s.notSampled.Load())

	if s.getResults != nil {
		results := s.getResults()
		traces := results.GetTraces()
		if (len(traces.ByParticipant)) != 0 {
			// whether or not these show up is timing dependent, but not important
			possibleTraces := map[string]struct{}{
				"Test Environment: Start":                                 {},
				"IDP: Server: POST /oidc/token":                           {},
				"IDP: Server: GET /oidc/userinfo":                         {},
				"Authenticate: OAuth2 Client: GET /.well-known/jwks.json": {},
			}
			actual := slices.Collect(maps.Keys(traces.ByName))
			for _, name := range actual {
				if _, ok := possibleTraces[name]; !ok {
					s.Fail("unexpected trace: " + name)
				}
			}
		}
	}
}

func TestSampling(t *testing.T) {
	suite.Run(t, &SamplingTestSuite{})
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

	env := testenv.New(t, testenv.WithTraceDebugFlags(testenv.StandardTraceDebugFlags|trace.EnvoyFlushEverySpan), testenv.WithTraceClient(newRemoteClient()))
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
		results := getResults()
		results.MatchTraces(t, MatchOptions{CheckDetachedSpans: true},
			Match{Name: "External: External Root", TraceCount: 1, Services: []string{
				"Authorize",
				"Authenticate",
				"Control Plane",
				"Data Broker",
				"Proxy",
				"IDP",
				"Envoy",
				"External",
				"HTTP Upstream",
			}},
		)
	}
}
