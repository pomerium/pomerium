package telemetry // import "github.com/pomerium/pomerium/internal/telemetry"

import (
	"fmt"
	"net/http"

	ocprom "contrib.go.opencensus.io/exporter/prometheus"
	prom "github.com/prometheus/client_golang/prometheus"
	"go.opencensus.io/stats/view"
)

func PrometheusHandler() (http.Handler, error) {
	if err := registerDefaultViews(); err != nil {
		return nil, fmt.Errorf("internal/telemetry: failed registering views")
	}
	reg := prom.DefaultRegisterer.(*prom.Registry)
	exporter, err := ocprom.NewExporter(
		ocprom.Options{
			Namespace: "pomerium",
			Registry:  reg,
		})
	if err != nil {
		return nil, fmt.Errorf("internal/telemetry: prometheus exporter: %v", err)
	}
	view.RegisterExporter(exporter)
	mux := http.NewServeMux()
	mux.Handle("/metrics", exporter)
	// todo: should be it's own http service... i know.
	// mux.Handle("/metrics/debug/", http.StripPrefix("/metrics/debug", zpages.Handler))
	return mux, nil
}
