package metrics

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"

	ocprom "contrib.go.opencensus.io/exporter/prometheus"
	prom "github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"go.opencensus.io/stats/view"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/metrics"

	log "github.com/pomerium/pomerium/internal/log"
)

// PrometheusHandler creates an exporter that exports stats to Prometheus
// and returns a handler suitable for exporting metrics.
func PrometheusHandler(envoyURL *url.URL, installationID string) (http.Handler, error) {
	exporter, err := getGlobalExporter()
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()

	envoyMetricsURL, err := envoyURL.Parse("/stats/prometheus")
	if err != nil {
		return nil, fmt.Errorf("telemetry/metrics: invalid proxy URL: %w", err)
	}

	mux.Handle("/metrics", newProxyMetricsHandler(exporter, *envoyMetricsURL, installationID))
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
func newProxyMetricsHandler(exporter *ocprom.Exporter, envoyURL url.URL, installationID string) http.HandlerFunc {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "__none__"
	}
	extraLabels := []*io_prometheus_client.LabelPair{{
		Name:  proto.String(metrics.InstallationIDLabel),
		Value: proto.String(installationID),
	}, {
		Name:  proto.String(metrics.HostnameLabel),
		Value: proto.String(hostname),
	}}

	return func(w http.ResponseWriter, r *http.Request) {
		// Ensure we don't get entangled with compression from ocprom
		r.Header.Del("Accept-Encoding")

		rec := httptest.NewRecorder()
		exporter.ServeHTTP(rec, r)

		err := writeMetricsWithLabels(w, rec.Body, extraLabels)
		if err != nil {
			log.Error(r.Context()).Err(err).Send()
			return
		}

		req, err := http.NewRequestWithContext(r.Context(), "GET", envoyURL.String(), nil)
		if err != nil {
			log.Error(r.Context()).Err(err).Msg("telemetry/metrics: failed to create request for envoy")
			return
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Error(r.Context()).Err(err).Msg("telemetry/metrics: fail to fetch proxy metrics")
			return
		}
		defer resp.Body.Close()

		err = writeMetricsWithLabels(w, resp.Body, extraLabels)
		if err != nil {
			log.Error(r.Context()).Err(err).Send()
			return
		}
	}
}

func writeMetricsWithLabels(w io.Writer, r io.Reader, extra []*io_prometheus_client.LabelPair) error {
	var parser expfmt.TextParser
	ms, err := parser.TextToMetricFamilies(r)
	if err != nil {
		return fmt.Errorf("telemetry/metric: failed to read prometheus metrics: %w", err)
	}

	for _, m := range ms {
		for _, mm := range m.Metric {
			mm.Label = append(mm.Label, extra...)
		}
		_, err = expfmt.MetricFamilyToText(w, m)
		if err != nil {
			return fmt.Errorf("telemetry/metric: failed to write prometheus metrics: %w", err)
		}
	}

	return nil
}
