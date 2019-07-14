package metrics // import "github.com/pomerium/pomerium/internal/metrics"

import (
	"net/http"

	ocProm "contrib.go.opencensus.io/exporter/prometheus"
	prom "github.com/prometheus/client_golang/prometheus"
	"go.opencensus.io/stats/view"
)

//NewPromHTTPListener creates a prometheus exporter on ListenAddr
func NewPromHTTPListener(addr string) error {
	return http.ListenAndServe(addr, newPromHTTPHandler())
}

// newPromHTTPHandler creates a new prometheus exporter handler for /metrics
func newPromHTTPHandler() http.Handler {
	// TODO this is a cheap way to get thorough go process
	// stats.  It will not work with additional exporters.
	// It should turn into an FR to the OC framework
	reg := prom.DefaultRegisterer.(*prom.Registry)
	pe, _ := ocProm.NewExporter(ocProm.Options{
		Namespace: "pomerium",
		Registry:  reg,
	})
	view.RegisterExporter(pe)
	mux := http.NewServeMux()
	mux.Handle("/metrics", pe)
	return mux
}
