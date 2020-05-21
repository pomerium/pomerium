package trace

import (
	"context"

	"go.opencensus.io/plugin/ochttp/propagation/b3"
	"go.opencensus.io/trace"
	"google.golang.org/grpc/metadata"
	grpcstats "google.golang.org/grpc/stats"
)

// GRPCServerTracingHandler implements stats.Handler methods for tracing
type GRPCServerTracingHandler struct {
	service string
}

// NewGRPCServerTracingHandler creates a new GRPCServerTracingHandler for a given service name
func NewGRPCServerTracingHandler(service string) *GRPCServerTracingHandler {
	return &GRPCServerTracingHandler{service: service}
}

// TagRPC handles adding any trace related values to the incoming context
func (h *GRPCServerTracingHandler) TagRPC(ctx context.Context, tagInfo *grpcstats.RPCTagInfo) context.Context {

	b3SpanContext, _ := b3SpanContextFromRPC(ctx)
	traceContext, _ := trace.StartSpanWithRemoteParent(ctx, h.service, b3SpanContext)

	return traceContext
}

func b3SpanContextFromRPC(ctx context.Context) (trace.SpanContext, bool) {
	m, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return trace.SpanContext{}, ok
	}

	traceIDHeaders := m.Get("x-b3-traceid")
	if len(traceIDHeaders) == 0 {
		return trace.SpanContext{}, ok
	}

	traceID, ok := b3.ParseTraceID(traceIDHeaders[0])
	if !ok {
		return trace.SpanContext{}, ok
	}

	spanIDHeaders := m.Get("x-b3-spanid")
	if len(spanIDHeaders) == 0 {
		return trace.SpanContext{}, ok
	}

	spanID, ok := b3.ParseSpanID(spanIDHeaders[0])
	if !ok {
		return trace.SpanContext{}, ok
	}

	sampled, _ := b3.ParseSampled(m.Get("x-b3-sampled")[0])

	traceCtx := trace.SpanContext{
		TraceID:      traceID,
		SpanID:       spanID,
		TraceOptions: sampled,
	}

	return traceCtx, ok
}
