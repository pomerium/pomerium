package trace_test

import (
	"context"
	"testing"

	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace/noop"
)

func TestUseGlobalPanicTracer(t *testing.T) {
	t.Cleanup(func() {
		otel.SetTracerProvider(noop.NewTracerProvider())
	})
	trace.UseGlobalPanicTracer()
	tracer := otel.GetTracerProvider().Tracer("test")
	assert.Panics(t, func() {
		tracer.Start(context.Background(), "span")
	})
}
