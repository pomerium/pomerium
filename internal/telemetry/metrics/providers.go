package metrics

import (
	"fmt"
	"net/http"

	ocprom "contrib.go.opencensus.io/exporter/prometheus"
	prom "github.com/prometheus/client_golang/prometheus"
	"go.opencensus.io/stats/view"
)

// PrometheusHandler creates an exporter that exports stats to Prometheus
// and returns a handler suitable for exporting metrics.
func PrometheusHandler() (http.Handler, error) {
	if err := registerDefaultViews(); err != nil {
		return nil, fmt.Errorf("telemetry/metrics: failed registering views")
	}
	reg := prom.DefaultRegisterer.(*prom.Registry)
	exporter, err := ocprom.NewExporter(
		ocprom.Options{
			Namespace: "pomerium",
			Registry:  reg,
		})
	if err != nil {
		return nil, fmt.Errorf("telemetry/metrics: prometheus exporter: %w", err)
	}
	view.RegisterExporter(exporter)
	mux := http.NewServeMux()
	mux.Handle("/metrics", exporter)
	return mux, nil
}

func registerDefaultViews() error {
	var views []*view.View
	for _, v := range DefaultViews {
		views = append(views, v...)
	}
	return view.Register(views...)
}
