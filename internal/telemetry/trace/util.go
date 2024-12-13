package trace

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"unique"

	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

func ParseTraceparent(traceparent string) (oteltrace.SpanContext, error) {
	parts := strings.Split(traceparent, "-")
	if len(parts) != 4 {
		return oteltrace.SpanContext{}, fmt.Errorf("malformed traceparent: expected 4 segments, found %d", len(parts))
	}
	traceID, err := oteltrace.TraceIDFromHex(parts[1])
	if err != nil {
		return oteltrace.SpanContext{}, fmt.Errorf("malformed traceparent: invalid trace ID: %w", err)
	}
	spanID, err := oteltrace.SpanIDFromHex(parts[2])
	if err != nil {
		return oteltrace.SpanContext{}, fmt.Errorf("malformed traceparent: invalid span ID: %w", err)
	}
	var traceFlags oteltrace.TraceFlags
	if flags, err := hex.DecodeString(parts[3]); err != nil {
		return oteltrace.SpanContext{}, fmt.Errorf("malformed traceparent: invalid trace flags: %w", err)
	} else if len(flags) == 1 {
		traceFlags = oteltrace.TraceFlags(flags[0])
	} else {
		return oteltrace.SpanContext{}, fmt.Errorf("malformed traceparent: invalid trace flags of size %d", len(flags))
	}
	if len(traceID) != 16 {
		return oteltrace.SpanContext{}, fmt.Errorf("malformed traceparent: invalid trace ID of size %d", len(traceID))
	}
	if len(spanID) != 8 {
		return oteltrace.SpanContext{}, fmt.Errorf("malformed traceparent: invalid span ID of size %d", len(spanID))
	}
	return oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: oteltrace.TraceFlags(traceFlags),
	}), nil
}

// WithTraceFromSpanContext returns a copy of traceparent with the trace ID
// (2nd segment) and trace flags (4th segment) replaced with the corresponding
// values from spanContext.
func WithTraceFromSpanContext(traceparent string, spanContext oteltrace.SpanContext) string {
	parts := strings.Split(traceparent, "-")
	if len(parts) != 4 {
		return traceparent
	}
	parts[1] = spanContext.TraceID().String()
	parts[3] = spanContext.TraceFlags().String()
	return strings.Join(parts, "-")
}

func FormatSpanName(span *tracev1.Span) {
	hasPath := strings.Contains(span.GetName(), "${path}")
	hasHost := strings.Contains(span.GetName(), "${host}")
	hasMethod := strings.Contains(span.GetName(), "${method}")
	if hasPath || hasHost || hasMethod {
		var u *url.URL
		var method string
		for _, attr := range span.Attributes {
			if attr.Key == "http.url" {
				u, _ = url.Parse(attr.Value.GetStringValue())
			}
			if attr.Key == "http.method" {
				method = attr.Value.GetStringValue()
			}
		}
		if u != nil {
			if hasPath {
				span.Name = strings.ReplaceAll(span.Name, "${path}", u.Path)
			}
			if hasHost {
				span.Name = strings.ReplaceAll(span.Name, "${host}", u.Host)
			}
			if hasMethod {
				span.Name = strings.ReplaceAll(span.Name, "${method}", method)
			}
		}
	}
}

var (
	zeroSpanID  oteltrace.SpanID
	zeroTraceID = unique.Make(oteltrace.TraceID([16]byte{}))
)

func ToSpanID(bytes []byte) (oteltrace.SpanID, bool) {
	switch len(bytes) {
	case 0:
		return zeroSpanID, true
	case 8:
		return oteltrace.SpanID(bytes), true
	}
	return zeroSpanID, false
}

func ToTraceID(bytes []byte) (unique.Handle[oteltrace.TraceID], bool) {
	switch len(bytes) {
	case 0:
		return zeroTraceID, true
	case 16:
		return unique.Make(oteltrace.TraceID(bytes)), true
	}
	return zeroTraceID, false
}

func NewAttributeSet(kvs ...*commonv1.KeyValue) attribute.Set {
	attrs := make([]attribute.KeyValue, len(kvs))
	for i, kv := range kvs {
		var value attribute.Value
		switch v := kv.Value.Value.(type) {
		case *commonv1.AnyValue_BoolValue:
			value = attribute.BoolValue(v.BoolValue)
		case *commonv1.AnyValue_BytesValue:
			value = attribute.StringValue(string(v.BytesValue))
		case *commonv1.AnyValue_DoubleValue:
			value = attribute.Float64Value(v.DoubleValue)
		case *commonv1.AnyValue_IntValue:
			value = attribute.Int64Value(v.IntValue)
		case *commonv1.AnyValue_StringValue:
			value = attribute.StringValue(v.StringValue)
		case *commonv1.AnyValue_ArrayValue:
			panic("unimplemented")
		case *commonv1.AnyValue_KvlistValue:
			panic("unimplemented")
		default:
			panic(fmt.Sprintf("unexpected v1.isAnyValue_Value: %#v", v))
		}
		attrs[i] = attribute.KeyValue{
			Key:   attribute.Key(kv.Key),
			Value: value,
		}
	}
	return attribute.NewSet(attrs...)
}
