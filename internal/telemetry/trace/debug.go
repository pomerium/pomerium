package trace

import (
	"context"
	"fmt"
	"runtime"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type stackTraceProcessor struct{}

// ForceFlush implements trace.SpanProcessor.
func (s *stackTraceProcessor) ForceFlush(ctx context.Context) error {
	return nil
}

// OnEnd implements trace.SpanProcessor.
func (*stackTraceProcessor) OnEnd(s sdktrace.ReadOnlySpan) {
}

// OnStart implements trace.SpanProcessor.
func (*stackTraceProcessor) OnStart(parent context.Context, s sdktrace.ReadWriteSpan) {
	_, file, line, _ := runtime.Caller(2)
	s.SetAttributes(attribute.String("caller", fmt.Sprintf("%s:%d", file, line)))
}

// Shutdown implements trace.SpanProcessor.
func (s *stackTraceProcessor) Shutdown(ctx context.Context) error {
	return nil
}
