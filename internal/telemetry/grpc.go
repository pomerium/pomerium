package telemetry

import (
	"context"

	"go.opencensus.io/plugin/ocgrpc"
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

	metricCtx := h.metricsHandler.TagRPC(ctx, tagInfo)
	handledCtx := h.Handler.TagRPC(metricCtx, tagInfo)

	return handledCtx
}

// NewGRPCServerStatsHandler creates a new GRPCServerStatsHandler for a pomerium service
func NewGRPCServerStatsHandler(service string) grpcstats.Handler {
	return &GRPCServerStatsHandler{
		service:        ServiceName(service),
		Handler:        &ocgrpc.ServerHandler{},
		metricsHandler: metrics.NewGRPCServerMetricsHandler(ServiceName(service)),
	}
}
