package telemetry

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opencensus.io/plugin/ocgrpc"
	"go.opencensus.io/plugin/ochttp/propagation/b3"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/metadata"
	grpcstats "google.golang.org/grpc/stats"
)

type mockTagHandler struct {
	called bool
}

type mockCtxTag string

func (m *mockTagHandler) TagRPC(ctx context.Context, _ *grpcstats.RPCTagInfo) context.Context {
	m.called = true
	return context.WithValue(ctx, mockCtxTag("added"), "true")
}

func Test_GRPCServerStatsHandler(t *testing.T) {
	metricsHandler := &mockTagHandler{}
	h := &GRPCServerStatsHandler{
		metricsHandler: metricsHandler,
		Handler:        &ocgrpc.ServerHandler{},
	}

	ctx := context.WithValue(context.Background(), mockCtxTag("original"), "true")
	ctx = metadata.NewIncomingContext(ctx, metadata.MD{
		b3TraceIDHeader: {"9de3f6756f315fef"},
		b3SpanIDHeader:  {"b4f83d3096b6bf9c"},
	})
	ctx = h.TagRPC(ctx, &grpcstats.RPCTagInfo{})

	assert.True(t, metricsHandler.called)
	assert.Equal(t, ctx.Value(mockCtxTag("added")), "true")
	assert.Equal(t, ctx.Value(mockCtxTag("original")), "true")

	span := trace.FromContext(ctx)
	expectedTraceID, _ := b3.ParseTraceID("9de3f6756f315fef")
	assert.Equal(t, expectedTraceID, span.SpanContext().TraceID)
}
