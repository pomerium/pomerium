package trace

import (
	"net/url"

	"go.opentelemetry.io/otel/propagation"
)

type PomeriumURLQueryCarrier url.Values

// Get implements propagation.TextMapCarrier.
func (q PomeriumURLQueryCarrier) Get(key string) string {
	return url.Values(q).Get("pomerium_" + key)
}

// Set implements propagation.TextMapCarrier.
func (q PomeriumURLQueryCarrier) Set(key string, value string) {
	url.Values(q).Set("pomerium_"+key, value)
}

// Keys implements propagation.TextMapCarrier.
func (q PomeriumURLQueryCarrier) Keys() []string {
	// this function is never called in otel, and the way it would be
	// implemented in this instance is unclear.
	panic("unimplemented")
}

var _ propagation.TextMapCarrier = PomeriumURLQueryCarrier{}
