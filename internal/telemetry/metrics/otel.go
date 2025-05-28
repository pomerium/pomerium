package metrics

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdk_metric "go.opentelemetry.io/otel/sdk/metric"
)

// Meter is the global meter for Pomerium.
var Meter metric.Meter

func init() {
	e, err := prometheus.New(prometheus.WithNamespace("pomerium"))
	if err != nil {
		panic(err)
	}

	otel.SetMeterProvider(sdk_metric.NewMeterProvider(
		sdk_metric.WithReader(e),
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
