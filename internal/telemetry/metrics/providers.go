package metrics

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	ocprom "contrib.go.opencensus.io/exporter/prometheus"
	prom "github.com/prometheus/client_golang/prometheus"
	"go.opencensus.io/stats/view"

	log "github.com/pomerium/pomerium/internal/log"
)

// PrometheusHandler creates an exporter that exports stats to Prometheus
// and returns a handler suitable for exporting metrics.
func PrometheusHandler(envoyURL *url.URL) (http.Handler, error) {
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

	envoyMetricsURL, err := envoyURL.Parse("/stats/prometheus")
	if err != nil {
		return nil, fmt.Errorf("telemetry/metrics: invalid proxy URL: %w", err)
	}

	mux.Handle("/metrics", newProxyMetricsHandler(exporter, *envoyMetricsURL))
	return mux, nil
}

func registerDefaultViews() error {
	var views []*view.View
	for _, v := range DefaultViews {
		views = append(views, v...)
	}
	return view.Register(views...)
}

// newProxyMetricsHandler creates a subrequest to the envoy control plane for metrics and
// combines them with our own
func newProxyMetricsHandler(promHandler http.Handler, envoyURL url.URL) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		defer promHandler.ServeHTTP(w, r)

		// Ensure we don't get entangled with compression from ocprom
		r.Header.Del("Accept-Encoding")

		r, err := http.NewRequestWithContext(r.Context(), "GET", envoyURL.String(), nil)
		if err != nil {
			log.Error().Err(err).Msg("telemetry/metrics: failed to create request for envoy")
			return
		}

		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			log.Error().Err(err).Msg("telemetry/metrics: fail to fetch proxy metrics")
			return
		}
		defer resp.Body.Close()

		envoyBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Error().Err(err).Msg("telemetry/metric: failed to read proxy metrics")
			return
		}

		w.Write(envoyBody)
	}
}
