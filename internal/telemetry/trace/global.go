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
