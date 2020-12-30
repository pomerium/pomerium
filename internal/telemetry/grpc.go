package telemetry

import (
	"context"

	"go.opencensus.io/plugin/ocgrpc"
	"google.golang.org/grpc"
	grpcstats "google.golang.org/grpc/stats"

	"github.com/pomerium/pomerium/internal/telemetry/metrics"
)

type tagRPCHandler interface {
	TagRPC(context.Context, *grpcstats.RPCTagInfo) context.Context
}

// GRPCServerStatsHandler provides a grpc stats.Handler for metrics and tracing for a pomerium service
type GRPCServerStatsHandler struct {
	service        string
	metricsHandler tagRPCHandler
	grpcstats.Handler
}

// TagRPC implements grpc.stats.Handler and adds metrics and tracing metadata to the context of a given RPC
func (h *GRPCServerStatsHandler) TagRPC(ctx context.Context, tagInfo *grpcstats.RPCTagInfo) context.Context {
	handledCtx := h.Handler.TagRPC(ctx, tagInfo)
	metricCtx := h.metricsHandler.TagRPC(handledCtx, tagInfo)

	return metricCtx
}

// NewGRPCServerStatsHandler creates a new GRPCServerStatsHandler for a pomerium service
func NewGRPCServerStatsHandler(service string) grpcstats.Handler {
	return &GRPCServerStatsHandler{
		service:        ServiceName(service),
		Handler:        &ocgrpc.ServerHandler{},
		metricsHandler: metrics.NewGRPCServerMetricsHandler(ServiceName(service)),
	}
}

// GRPCClientStatsHandler provides DialOptions for grpc clients to instrument network calls with
// both metrics and tracing
type GRPCClientStatsHandler struct {
	UnaryInterceptor grpc.UnaryClientInterceptor
	// TODO: we should have a streaming interceptor too
	grpcstats.Handler
}

// NewGRPCClientStatsHandler returns a new GRPCClientStatsHandler used to create
// telemetry related client DialOptions
func NewGRPCClientStatsHandler(service string) *GRPCClientStatsHandler {
	return &GRPCClientStatsHandler{
		Handler:          &ocgrpc.ClientHandler{},
		UnaryInterceptor: metrics.GRPCClientInterceptor(ServiceName(service)),
	}
}
