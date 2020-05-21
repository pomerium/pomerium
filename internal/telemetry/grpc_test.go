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

func (m *mockTagHandler) TagRPC(ctx context.Context, tagInfo *grpcstats.RPCTagInfo) context.Context {
	m.called = true
	return ctx
}

func Test_GRPCServerStatsHandler(t *testing.T) {

	metricsHandler := &mockTagHandler{}
	traceHandler := &mockTagHandler{}
	h := &GRPCServerStatsHandler{
		metricsHandler: metricsHandler,
		traceHandler:   traceHandler,
		Handler:        &ocgrpc.ServerHandler{},
	}
	h.TagRPC(context.Background(), &grpcstats.RPCTagInfo{})

	assert.True(t, metricsHandler.called)
	assert.True(t, traceHandler.called)
}
