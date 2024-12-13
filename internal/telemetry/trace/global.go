package trace

import (
	"context"

	"go.opentelemetry.io/contrib/propagators/autoprop"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/embedded"
)

// PomeriumCoreTracer should be used for all tracers created in pomerium core.
const PomeriumCoreTracer = "pomerium.io/core"

func init() {
	otel.SetTextMapPropagator(autoprop.NewTextMapPropagator())
}

// Continue starts a new span using the tracer provider of the span in the given
// context.
//
// In most cases, it is better to start spans directly from a specific tracer,
// obtained via dependency injection or some other mechanism. This function is
// useful in shared code where the tracer used to start the span is not
// necessarily the same every time, but can change based on the call site.
func Continue(ctx context.Context, name string, o ...trace.SpanStartOption) (context.Context, trace.Span) {
	return trace.SpanFromContext(ctx).TracerProvider().Tracer(PomeriumCoreTracer).Start(ctx, name, o...)
}

// UseGlobalPanicTracer sets the global tracer provider to one whose tracers
// panic when starting spans. This can be used to locate errant usages of the
// global tracer, and is enabled automatically in some tests. It is otherwise
// not used by default, since pomerium is used as a library in some places that
// might use the global tracer provider.
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

var _ trace.Tracer = panicTracer{}

// Start implements trace.Tracer.
func (p panicTracer) Start(context.Context, string, ...trace.SpanStartOption) (context.Context, trace.Span) {
	panic("global tracer used")
}
