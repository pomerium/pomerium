package trace

import (
	"context"

	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/embedded"
)

const PomeriumCoreTracer = "pomerium.io/core"

type panicTracerProvider struct {
	embedded.TracerProvider
}

// Tracer implements trace.TracerProvider.
func (w panicTracerProvider) Tracer(name string, options ...trace.TracerOption) trace.Tracer {
	return panicTracer{}
}

type panicTracer struct {
	embedded.Tracer
}

// Start implements trace.Tracer.
func (p panicTracer) Start(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	panic("global tracer used")
}

func Continue(ctx context.Context, name string, o ...trace.SpanStartOption) (context.Context, trace.Span) {
	return trace.SpanFromContext(ctx).TracerProvider().Tracer(PomeriumCoreTracer).Start(ctx, name, o...)
}
