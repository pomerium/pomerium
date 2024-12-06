package trace

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/embedded"
)

const PomeriumCoreTracer = "pomerium.io/core"

func init() {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
}

func Continue(ctx context.Context, name string, o ...trace.SpanStartOption) (context.Context, trace.Span) {
	return trace.SpanFromContext(ctx).TracerProvider().Tracer(PomeriumCoreTracer).Start(ctx, name, o...)
}

func UseGlobalPanicTracer() {
	otel.SetTracerProvider(panicTracerProvider{})
}

type panicTracerProvider struct {
	embedded.TracerProvider
}

// Tracer implements trace.TracerProvider.
func (w panicTracerProvider) Tracer(string, ...trace.TracerOption) trace.Tracer {
	return panicTracer{}
}

type panicTracer struct {
	embedded.Tracer
}

// Start implements trace.Tracer.
func (p panicTracer) Start(context.Context, string, ...trace.SpanStartOption) (context.Context, trace.Span) {
	panic("global tracer used")
}
