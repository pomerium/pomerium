package telemetry

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opencensus.io/plugin/ocgrpc"
	grpcstats "google.golang.org/grpc/stats"
)

type mockTagHandler struct {
	called bool
}

type mockCtxTag string

func (m *mockTagHandler) TagRPC(ctx context.Context, tagInfo *grpcstats.RPCTagInfo) context.Context {
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
	ctx = h.TagRPC(ctx, &grpcstats.RPCTagInfo{})

	assert.True(t, metricsHandler.called)
	assert.Equal(t, ctx.Value(mockCtxTag("added")), "true")
	assert.Equal(t, ctx.Value(mockCtxTag("original")), "true")
}
