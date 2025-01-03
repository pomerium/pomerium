package trace_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/test/bufconn"
)

var cases = []struct {
	name                   string
	setTraceparent         string
	setPomeriumTraceparent string
	check                  func(t testing.TB, ctx context.Context)
}{
	{
		name:           "x-pomerium-traceparent not present",
		setTraceparent: Traceparent(Trace(1), Span(1), true),
		check: func(t testing.TB, ctx context.Context) {
			span := oteltrace.SpanFromContext(ctx)
			assert.Equal(t, Trace(1).ID().Value(), span.SpanContext().TraceID())
			assert.Equal(t, Span(1).ID(), span.SpanContext().SpanID())
			assert.True(t, span.SpanContext().IsSampled())
		},
	},
	{
		name:                   "x-pomerium-traceparent present",
		setTraceparent:         Traceparent(Trace(2), Span(2), true),
		setPomeriumTraceparent: Traceparent(Trace(1), Span(1), true),
		check: func(t testing.TB, ctx context.Context) {
			span := oteltrace.SpanFromContext(ctx)
			assert.Equal(t, Trace(1).ID().Value(), span.SpanContext().TraceID())
			assert.Equal(t, Span(2).ID(), span.SpanContext().SpanID())
			assert.True(t, span.SpanContext().IsSampled())
		},
	},
	{
		name:                   "x-pomerium-traceparent present, force sampling off",
		setTraceparent:         Traceparent(Trace(2), Span(2), true),
		setPomeriumTraceparent: Traceparent(Trace(1), Span(1), false),
		check: func(t testing.TB, ctx context.Context) {
			span := oteltrace.SpanFromContext(ctx)
			assert.Equal(t, Trace(1).ID().Value(), span.SpanContext().TraceID())
			assert.Equal(t, Span(2).ID(), span.SpanContext().SpanID())
			assert.Equal(t, false, span.SpanContext().IsSampled())
		},
	},
	{
		name:                   "x-pomerium-traceparent present, force sampling on",
		setTraceparent:         Traceparent(Trace(2), Span(2), false),
		setPomeriumTraceparent: Traceparent(Trace(1), Span(1), true),
		check: func(t testing.TB, ctx context.Context) {
			span := oteltrace.SpanFromContext(ctx)
			assert.Equal(t, Trace(1).ID().Value(), span.SpanContext().TraceID())
			assert.Equal(t, Span(2).ID(), span.SpanContext().SpanID())
			assert.Equal(t, true, span.SpanContext().IsSampled())
		},
	},
	{
		name:                   "malformed x-pomerium-traceparent",
		setTraceparent:         Traceparent(Trace(2), Span(2), false),
		setPomeriumTraceparent: "00-xxxxxx-yyyyyy-03",
		check: func(t testing.TB, ctx context.Context) {
			span := oteltrace.SpanFromContext(ctx)
			assert.Equal(t, Trace(2).ID().Value(), span.SpanContext().TraceID())
			assert.Equal(t, Span(2).ID(), span.SpanContext().SpanID())
			assert.Equal(t, false, span.SpanContext().IsSampled())
		},
	},
}

func TestHTTPMiddleware(t *testing.T) {
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/foo", nil)
			if tc.setTraceparent != "" {
				r.Header.Add("Traceparent", tc.setTraceparent)
			}
			if tc.setPomeriumTraceparent != "" {
				r.Header.Add("X-Pomerium-Traceparent", tc.setPomeriumTraceparent)
			}
			w := httptest.NewRecorder()
			trace.NewHTTPMiddleware(
				otelhttp.WithTracerProvider(noop.NewTracerProvider()),
			)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				tc.check(t, r.Context())
			})).ServeHTTP(w, r)
		})
	}
}

func TestGRPCMiddleware(t *testing.T) {
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := grpc.NewServer(
				grpc.StatsHandler(trace.NewServerStatsHandler(otelgrpc.NewServerHandler(
					otelgrpc.WithTracerProvider(noop.NewTracerProvider())))),
				grpc.Creds(insecure.NewCredentials()),
			)
			lis := bufconn.Listen(4096)
			grpc_testing.RegisterTestServiceServer(srv, &testServer{
				fn: func(ctx context.Context) {
					tc.check(t, ctx)
				},
			})
			go srv.Serve(lis)
			t.Cleanup(srv.Stop)

			client, err := grpc.NewClient("passthrough://ignore",
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithStatsHandler(otelgrpc.NewClientHandler(
					otelgrpc.WithTracerProvider(noop.NewTracerProvider()))),
				grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
					return lis.DialContext(ctx)
				}),
			)
			require.NoError(t, err)

			ctx := context.Background()
			if tc.setTraceparent != "" {
				ctx = metadata.AppendToOutgoingContext(ctx,
					"traceparent", tc.setTraceparent,
				)
			}
			if tc.setPomeriumTraceparent != "" {
				ctx = metadata.AppendToOutgoingContext(ctx,
					"x-pomerium-traceparent", tc.setPomeriumTraceparent,
				)
			}
			_, err = grpc_testing.NewTestServiceClient(client).EmptyCall(ctx, &grpc_testing.Empty{})
			assert.NoError(t, err)
		})
	}
}

type testServer struct {
	grpc_testing.UnimplementedTestServiceServer
	fn func(ctx context.Context)
}

func (ts *testServer) EmptyCall(ctx context.Context, _ *grpc_testing.Empty) (*grpc_testing.Empty, error) {
	ts.fn(ctx)
	return &grpc_testing.Empty{}, nil
}

type mockHandler struct {
	handleConn func(ctx context.Context, stats stats.ConnStats)
	handleRPC  func(ctx context.Context, stats stats.RPCStats)
	tagConn    func(ctx context.Context, info *stats.ConnTagInfo) context.Context
	tagRPC     func(ctx context.Context, info *stats.RPCTagInfo) context.Context
}

// HandleConn implements stats.Handler.
func (m *mockHandler) HandleConn(ctx context.Context, stats stats.ConnStats) {
	m.handleConn(ctx, stats)
}

// HandleRPC implements stats.Handler.
func (m *mockHandler) HandleRPC(ctx context.Context, stats stats.RPCStats) {
	m.handleRPC(ctx, stats)
}

// TagConn implements stats.Handler.
func (m *mockHandler) TagConn(ctx context.Context, info *stats.ConnTagInfo) context.Context {
	return m.tagConn(ctx, info)
}

// TagRPC implements stats.Handler.
func (m *mockHandler) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	return m.tagRPC(ctx, info)
}

var _ stats.Handler = (*mockHandler)(nil)

func TestStatsInterceptor(t *testing.T) {
	var outBegin *stats.Begin
	var outEnd *stats.End
	base := &mockHandler{
		handleRPC: func(_ context.Context, rs stats.RPCStats) {
			switch rs := rs.(type) {
			case *stats.Begin:
				outBegin = rs
			case *stats.End:
				outEnd = rs
			}
		},
	}
	interceptor := func(_ context.Context, rs stats.RPCStats) stats.RPCStats {
		switch rs := rs.(type) {
		case *stats.Begin:
			return &stats.Begin{
				Client:                    rs.Client,
				BeginTime:                 rs.BeginTime.Add(-1 * time.Minute),
				FailFast:                  rs.FailFast,
				IsClientStream:            rs.IsClientStream,
				IsServerStream:            rs.IsServerStream,
				IsTransparentRetryAttempt: rs.IsTransparentRetryAttempt,
			}
		case *stats.End:
			return &stats.End{
				Client:    rs.Client,
				BeginTime: rs.BeginTime,
				EndTime:   rs.EndTime,
				Trailer:   rs.Trailer,
				Error:     errors.New("modified"),
			}
		}
		return rs
	}
	handler := trace.NewClientStatsHandler(
		base,
		trace.WithStatsInterceptor(interceptor),
	)
	inBegin := &stats.Begin{
		Client:                    true,
		BeginTime:                 time.Now(),
		FailFast:                  true,
		IsClientStream:            true,
		IsServerStream:            false,
		IsTransparentRetryAttempt: false,
	}
	handler.HandleRPC(context.Background(), inBegin)
	assert.NotNil(t, outBegin)
	assert.NotSame(t, inBegin, outBegin)
	assert.Equal(t, inBegin.BeginTime.Add(-1*time.Minute), outBegin.BeginTime)
	assert.Equal(t, inBegin.Client, outBegin.Client)
	assert.Equal(t, inBegin.FailFast, outBegin.FailFast)
	assert.Equal(t, inBegin.IsClientStream, outBegin.IsClientStream)
	assert.Equal(t, inBegin.IsServerStream, outBegin.IsServerStream)
	assert.Equal(t, inBegin.IsTransparentRetryAttempt, outBegin.IsTransparentRetryAttempt)

	inEnd := &stats.End{
		Client:    true,
		BeginTime: time.Now(),
		EndTime:   time.Now().Add(1 * time.Minute),
		Trailer:   metadata.Pairs("a", "b", "c", "d"),
		Error:     errors.New("input"),
	}
	handler.HandleRPC(context.Background(), inEnd)
	assert.NotNil(t, outEnd)
	assert.NotSame(t, inEnd, outEnd)
	assert.Equal(t, inEnd.Client, outEnd.Client)
	assert.Equal(t, inEnd.BeginTime, outEnd.BeginTime)
	assert.Equal(t, inEnd.EndTime, outEnd.EndTime)
	assert.Equal(t, inEnd.Trailer, outEnd.Trailer)
	assert.Equal(t, "input", inEnd.Error.Error())
	assert.Equal(t, "modified", outEnd.Error.Error())
}

func TestStatsInterceptor_Nil(t *testing.T) {
	var outCtx context.Context
	var outConnStats stats.ConnStats
	var outRPCStats stats.RPCStats
	var outConnTagInfo *stats.ConnTagInfo
	var outRPCTagInfo *stats.RPCTagInfo
	base := &mockHandler{
		handleConn: func(ctx context.Context, stats stats.ConnStats) {
			outCtx = ctx
			outConnStats = stats
		},
		handleRPC: func(ctx context.Context, stats stats.RPCStats) {
			outCtx = ctx
			outRPCStats = stats
		},
		tagConn: func(ctx context.Context, info *stats.ConnTagInfo) context.Context {
			outCtx = ctx
			outConnTagInfo = info
			return ctx
		},
		tagRPC: func(ctx context.Context, info *stats.RPCTagInfo) context.Context {
			outCtx = ctx
			outRPCTagInfo = info
			return ctx
		},
	}
	handler := trace.NewClientStatsHandler(
		base,
		trace.WithStatsInterceptor(nil),
	)

	inCtx := context.Background()
	inConnStats := &stats.ConnBegin{}
	inRPCStats := &stats.Begin{}
	inConnTagInfo := &stats.ConnTagInfo{}
	inRPCTagInfo := &stats.RPCTagInfo{}

	handler.HandleConn(inCtx, inConnStats)
	assert.Equal(t, inCtx, outCtx)
	assert.Same(t, inConnStats, outConnStats)

	handler.HandleRPC(inCtx, inRPCStats)
	assert.Equal(t, inCtx, outCtx)
	assert.Same(t, inRPCStats, outRPCStats)

	handler.TagConn(inCtx, inConnTagInfo)
	assert.Equal(t, inCtx, outCtx)
	assert.Same(t, inConnTagInfo, outConnTagInfo)

	handler.TagRPC(inCtx, inRPCTagInfo)
	assert.Equal(t, inCtx, outCtx)
	assert.Same(t, inRPCTagInfo, outRPCTagInfo)
}

func TestStatsInterceptor_Bug(t *testing.T) {
	handler := trace.NewClientStatsHandler(
		&mockHandler{
			handleRPC: func(_ context.Context, _ stats.RPCStats) {
				t.Error("should not be reached")
			},
		},
		trace.WithStatsInterceptor(func(_ context.Context, rs stats.RPCStats) stats.RPCStats {
			_ = rs.(*stats.Begin)
			return &stats.End{}
		}),
	)
	assert.PanicsWithValue(t, "bug: stats interceptor returned a message of a different type", func() {
		handler.HandleRPC(context.Background(), &stats.Begin{})
	})
}
