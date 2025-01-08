package trace

import (
	"unique"

	oteltrace "go.opentelemetry.io/otel/trace"
)

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
