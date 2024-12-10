package trace

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
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
		return oteltrace.SpanContext{}, errors.New("malformed traceparent")
	}
	traceID, err := oteltrace.TraceIDFromHex(parts[1])
	if err != nil {
		return oteltrace.SpanContext{}, err
	}
	spanID, err := oteltrace.SpanIDFromHex(parts[2])
	if err != nil {
		return oteltrace.SpanContext{}, err
	}
	traceFlags, err := strconv.ParseUint(parts[3], 6, 32)
	if err != nil {
		return oteltrace.SpanContext{}, err
	}
	if len(traceID) != 16 || len(spanID) != 8 {
		return oteltrace.SpanContext{}, errors.New("malformed traceparent")
	}
	return oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: oteltrace.TraceFlags(traceFlags),
	}), nil
}

func ReplaceTraceID(traceparent string, newTraceID oteltrace.TraceID) string {
	parts := strings.Split(traceparent, "-")
	if len(parts) != 4 {
		return traceparent
	}
	parts[1] = hex.EncodeToString(newTraceID[:])
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
