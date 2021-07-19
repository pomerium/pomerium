package telemetry

import (
	"context"
	"strings"

	"go.opencensus.io/plugin/ocgrpc"
	"go.opencensus.io/plugin/ochttp/propagation/b3"
	"go.opencensus.io/trace"
	"go.opencensus.io/trace/propagation"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	grpcstats "google.golang.org/grpc/stats"

	"github.com/pomerium/pomerium/internal/telemetry/metrics"
)

const (
	grpcTraceBinHeader = "grpc-trace-bin"
	b3TraceIDHeader    = "x-b3-traceid"
	b3SpanIDHeader     = "x-b3-spanid"
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
	// the opencensus trace handler only supports grpc-trace-bin, so we use that code and support b3 too

	md, _ := metadata.FromIncomingContext(ctx)
	name := strings.TrimPrefix(tagInfo.FullMethodName, "/")
	name = strings.Replace(name, "/", ".", -1)

	var parent trace.SpanContext
	hasParent := false
	if traceBin := md[grpcTraceBinHeader]; len(traceBin) > 0 {
		parent, hasParent = propagation.FromBinary([]byte(traceBin[0]))
	}

	if hdr := md[b3TraceIDHeader]; len(hdr) > 0 {
		if tid, ok := b3.ParseTraceID(hdr[0]); ok {
			parent.TraceID = tid
			hasParent = true
		}
	}
	if hdr := md[b3SpanIDHeader]; len(hdr) > 0 {
		if sid, ok := b3.ParseSpanID(hdr[0]); ok {
			parent.SpanID = sid
			hasParent = true
		}
	}

	if hasParent {
		ctx, _ = trace.StartSpanWithRemoteParent(ctx, name, parent,
			trace.WithSpanKind(trace.SpanKindServer))
	} else {
		ctx, _ = trace.StartSpan(ctx, name,
			trace.WithSpanKind(trace.SpanKindServer))
	}

	metricCtx := h.metricsHandler.TagRPC(ctx, tagInfo)
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
