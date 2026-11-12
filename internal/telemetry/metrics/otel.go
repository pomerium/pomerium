package metrics

import (
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdk_metric "go.opentelemetry.io/otel/sdk/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
)

// Meter is the global meter for Pomerium.
var Meter metric.Meter

// httpServerAddressView drops server.address and server.port from otelhttp
// server metrics. otelhttp takes both from the request Host header, which is
// client-controlled; the semantic conventions make them opt-in on server
// metrics for that reason.
var httpServerAddressView = sdk_metric.NewView(
	sdk_metric.Instrument{
		Name:  "http.server.*",
		Scope: instrumentation.Scope{Name: otelhttp.ScopeName},
	},
	sdk_metric.Stream{
		AttributeFilter: attribute.NewDenyKeysFilter(semconv.ServerAddressKey, semconv.ServerPortKey),
	},
)

func init() {
	e, err := prometheus.New(
		prometheus.WithNamespace("pomerium"),
		prometheus.WithoutUnits(),
		prometheus.WithoutScopeInfo(),
	)
	if err != nil {
		panic(err)
	}

	otel.SetMeterProvider(sdk_metric.NewMeterProvider(
		sdk_metric.WithReader(e),
		sdk_metric.WithView(httpServerAddressView),
	))

	Meter = otel.Meter("")
}

// Int64Counter returns an int64 counter.
func Int64Counter(name string, options ...metric.Int64CounterOption) metric.Int64Counter {
	c, err := Meter.Int64Counter(name, options...)
	if err != nil {
		panic(err)
	}
	return c
}

// Int64Histogram returns an int64 histogram.
func Int64Histogram(name string, options ...metric.Int64HistogramOption) metric.Int64Histogram {
	c, err := Meter.Int64Histogram(name, options...)
	if err != nil {
		panic(err)
	}
	return c
}
