package trace

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/trace"
)

func ParseTraceparent(traceparent string) (trace.SpanContext, error) {
	parts := strings.Split(traceparent, "-")
	if len(parts) != 4 {
		return trace.SpanContext{}, errors.New("malformed traceparent")
	}
	traceId, err := trace.TraceIDFromHex(parts[1])
	if err != nil {
		return trace.SpanContext{}, err
	}
	spanId, err := trace.SpanIDFromHex(parts[2])
	if err != nil {
		return trace.SpanContext{}, err
	}
	traceFlags, err := strconv.ParseUint(parts[3], 6, 32)
	if err != nil {
		return trace.SpanContext{}, err
	}
	if len(traceId) != 16 || len(spanId) != 8 {
		return trace.SpanContext{}, errors.New("malformed traceparent")
	}
	return trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceId,
		SpanID:     spanId,
		TraceFlags: trace.TraceFlags(traceFlags),
	}), nil
}

func ReplaceTraceID(traceparent string, newTraceID trace.TraceID) string {
	parts := strings.Split(traceparent, "-")
	if len(parts) != 4 {
		return traceparent
	}
	parts[1] = hex.EncodeToString(newTraceID[:])
	return strings.Join(parts, "-")
}
