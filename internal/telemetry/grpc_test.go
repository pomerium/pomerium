package telemetry

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opencensus.io/plugin/ocgrpc"
	"google.golang.org/grpc"
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

type mockDialOption struct {
	name string
	grpc.EmptyDialOption
}

func Test_NewGRPCClientStatsHandler(t *testing.T) {
	t.Parallel()

	h := NewGRPCClientStatsHandler("test")

	origOpts := []grpc.DialOption{
		mockDialOption{name: "one"},
		mockDialOption{name: "two"},
	}

	newOpts := h.DialOptions(origOpts...)

	for i := range origOpts {
		assert.Contains(t, newOpts, origOpts[i])
	}

	assert.Greater(t, len(newOpts), len(origOpts))
}
