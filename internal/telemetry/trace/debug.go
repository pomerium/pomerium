package trace

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type DebugFlags uint32

const (
	// If set, adds the "caller" attribute to each trace with the source location
	// where the trace was started.
	TrackSpanCallers = (1 << iota)

	// If set, keeps track of all span references and will attempt to wait for
	// all traces to complete when shutting down a trace context.
	// Use with caution, this will cause increasing memory usage over time.
	TrackSpanReferences = (1 << iota)

	// If set, keeps track of all observed spans, including span context and
	// all attributes.
	// Use with caution, this will cause significantly increasing memory usage
	// over time.
	TrackAllSpans = (1 << iota) | TrackSpanCallers

	// If set, will log all trace ID mappings on close.
	LogTraceIDMappings = (1 << iota)

	// If set, will log all spans observed by the exporter on close. These spans
	// may belong to incomplete traces.
	//
	// Enables [TrackAllSpans]
	LogAllSpans = (1 << iota) | TrackAllSpans

	// If set, will log the raw json payloads and timestamps of export requests
	// on close.
	// Use with caution, this will cause significantly increasing memory usage
	// over time.
	LogAllEvents = (1 << iota)

	// If set, will log all exported spans when a warning is issued on close
	// (requires warning flags to also be set)
	//
	// Enables [TrackAllSpans]
	LogAllSpansOnWarn = (1 << iota) | TrackAllSpans

	// If set, will log all trace ID mappings when a warning is issued on close.
	// (requires warning flags to also be set)
	LogTraceIDMappingsOnWarn = (1 << iota)

	// If set, will print a warning to stderr on close if there are any incomplete
	// traces (traces with no observed root spans)
	WarnOnIncompleteTraces = (1 << iota)

	// If set, will print a warning to stderr on close if there are any incomplete
	// spans (spans started, but not ended)
	WarnOnIncompleteSpans = (1 << iota)

	// If set, will print a warning to stderr on close if there are any spans
	// which reference unknown parent spans.
	//
	// Enables [TrackSpanReferences]
	WarnOnUnresolvedReferences = (1 << iota) | TrackSpanReferences

	// If set, configures Envoy to flush every span individually, disabling its
	// internal buffer.
	EnvoyFlushEverySpan = (1 << iota)
)

func (df DebugFlags) Check(flags DebugFlags) bool {
	return (df & flags) == flags
}

type stackTraceProcessor struct{}

// ForceFlush implements trace.SpanProcessor.
func (s *stackTraceProcessor) ForceFlush(context.Context) error {
	return nil
}

// OnEnd implements trace.SpanProcessor.
func (*stackTraceProcessor) OnEnd(sdktrace.ReadOnlySpan) {
}

// OnStart implements trace.SpanProcessor.
func (*stackTraceProcessor) OnStart(_ context.Context, s sdktrace.ReadWriteSpan) {
	_, file, line, _ := runtime.Caller(2)
	s.SetAttributes(attribute.String("caller", fmt.Sprintf("%s:%d", file, line)))
}

// Shutdown implements trace.SpanProcessor.
func (s *stackTraceProcessor) Shutdown(context.Context) error {
	return nil
}

var debugMessageWriter io.Writer

func startMsg(title string) *strings.Builder {
	msg := &strings.Builder{}
	msg.WriteString("\n==================================================\n")
	msg.WriteString(title)
	return msg
}

func endMsg(msg *strings.Builder) {
	msg.WriteString("==================================================\n")
	w := debugMessageWriter
	if w == nil {
		w = os.Stderr
	}
	fmt.Fprint(w, msg.String())
}
