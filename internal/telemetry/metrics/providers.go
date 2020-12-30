package metrics

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"

	ocprom "contrib.go.opencensus.io/exporter/prometheus"
	prom "github.com/prometheus/client_golang/prometheus"
	"go.opencensus.io/stats/view"

	log "github.com/pomerium/pomerium/internal/log"
)

// PrometheusHandler creates an exporter that exports stats to Prometheus
// and returns a handler suitable for exporting metrics.
func PrometheusHandler(envoyURL *url.URL) (http.Handler, error) {
	exporter, err := getGlobalExporter()
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()

	envoyMetricsURL, err := envoyURL.Parse("/stats/prometheus")
	if err != nil {
		return nil, fmt.Errorf("telemetry/metrics: invalid proxy URL: %w", err)
	}

	mux.Handle("/metrics", newProxyMetricsHandler(exporter, *envoyMetricsURL))
	return mux, nil
}

var (
	globalExporter     *ocprom.Exporter
	globalExporterErr  error
	globalExporterOnce sync.Once
)

func getGlobalExporter() (*ocprom.Exporter, error) {
	globalExporterOnce.Do(func() {
		globalExporterErr = registerDefaultViews()
		if globalExporterErr != nil {
			globalExporterErr = fmt.Errorf("telemetry/metrics: failed registering views: %w", globalExporterErr)
			return
		}

		reg := prom.DefaultRegisterer.(*prom.Registry)
		globalExporter, globalExporterErr = ocprom.NewExporter(
			ocprom.Options{
				Namespace: "pomerium",
				Registry:  reg,
			})
		if globalExporterErr != nil {
			globalExporterErr = fmt.Errorf("telemetry/metrics: prometheus exporter: %w", globalExporterErr)
			return
		}

		view.RegisterExporter(globalExporter)
	})
	return globalExporter, globalExporterErr
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
