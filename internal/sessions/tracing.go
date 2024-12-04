package sessions

import "go.opentelemetry.io/otel/propagation"

type SessionStateCarrier struct {
	*State
}

// Get implements propagation.TextMapCarrier.
func (s SessionStateCarrier) Get(key string) string {
	switch key {
	case "pomerium_traceparent":
		return s.Traceparent
	case "pomerium_tracestate":
		return s.Tracestate
	}
	return ""
}

// Set implements propagation.TextMapCarrier.
func (s SessionStateCarrier) Set(key string, value string) {
	switch key {
	case "pomerium_traceparent":
		s.Traceparent = value
	case "pomerium_tracestate":
		s.Tracestate = value
	}
}

// Keys implements propagation.TextMapCarrier.
func (s SessionStateCarrier) Keys() []string {
	return nil
}

var _ propagation.TextMapCarrier = SessionStateCarrier{}
