package trace_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/pomerium/pomerium/pkg/telemetry/trace"
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
