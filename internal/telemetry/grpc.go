package telemetry

import (
	"context"

	"go.opencensus.io/plugin/ocgrpc"
	grpcstats "google.golang.org/grpc/stats"

	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
)

type tagRPCHandler interface {
	TagRPC(context.Context, *grpcstats.RPCTagInfo) context.Context
}

// GRPCServerStatsHandler provides a grpc stats.Handler for metrics and tracing for a pomerium service
type GRPCServerStatsHandler struct {
	service        string
	metricsHandler tagRPCHandler
	traceHandler   tagRPCHandler
	grpcstats.Handler
}

// TagRPC implements grpc.stats.Handler and adds tags to the context of a given RPC
func (h *GRPCServerStatsHandler) TagRPC(ctx context.Context, tagInfo *grpcstats.RPCTagInfo) context.Context {

	traceCtx := h.traceHandler.TagRPC(ctx, tagInfo)
	handledCtx := h.Handler.TagRPC(traceCtx, tagInfo)
	taggedCtx := h.metricsHandler.TagRPC(handledCtx, tagInfo)

	return taggedCtx
}

// NewGRPCServerStatsHandler creates a new GRPCServerStatsHandler for a pomerium service
func NewGRPCServerStatsHandler(service string) grpcstats.Handler {
	return &GRPCServerStatsHandler{
		service:        service,
		Handler:        &ocgrpc.ServerHandler{},
		metricsHandler: metrics.NewGRPCServerMetricsHandler(service),
		traceHandler:   trace.NewGRPCServerTracingHandler(service),
	}
}
