package trace_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"

	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

func TestHTTPMiddleware(t *testing.T) {
	t.Parallel()

	router := mux.NewRouter()
	tp := sdktrace.NewTracerProvider()
	router.Use(trace.NewHTTPMiddleware(
		otelhttp.WithTracerProvider(tp),
	))
	router.Path("/foo").HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		span := oteltrace.SpanFromContext(r.Context())
		assert.Equal(t, "Server: GET /foo", span.(interface{ Name() string }).Name())
	}).Methods(http.MethodGet)
	w := httptest.NewRecorder()
	ctx, span := tp.Tracer("test").Start(t.Context(), "test")
	router.ServeHTTP(w, httptest.NewRequestWithContext(ctx, http.MethodGet, "/foo", nil))
	span.End()
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
	t.Parallel()

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
	handler.HandleRPC(t.Context(), inBegin)
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
	handler.HandleRPC(t.Context(), inEnd)
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
	t.Parallel()

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

	inCtx := t.Context()
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
	t.Parallel()

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
		handler.HandleRPC(t.Context(), &stats.Begin{})
	})
}
