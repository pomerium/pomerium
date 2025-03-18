package metrics

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	ocprom "contrib.go.opencensus.io/exporter/prometheus"
	"github.com/hashicorp/go-multierror"
	prom "github.com/prometheus/client_golang/prometheus"
	"go.opencensus.io/stats/view"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/prometheus"
)

// EnvoyMetricsPath is the path on the metrics listener that retrieves envoy metrics.
const EnvoyMetricsPath = "/metrics/envoy"

// ScrapeEndpoint external endpoints to scrape and decorate
type ScrapeEndpoint struct {
	// Name is the logical name of the endpoint
	Name string
	// URL of the endpoint to scrape that must output a prometheus-style metrics
	URL url.URL
	// Labels to append to each metric records
	Labels map[string]string
}

func (e *ScrapeEndpoint) String() string {
	return fmt.Sprintf("%s(%s)", e.Name, e.URL.String())
}

// PrometheusHandler creates an exporter that exports stats to Prometheus
// and returns a handler suitable for exporting metrics.
func PrometheusHandler(endpoints []ScrapeEndpoint, timeout time.Duration, labels map[string]string) (http.Handler, error) {
	exporter, err := getGlobalExporter()
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()

	mux.Handle("/metrics", newProxyMetricsHandler(exporter, endpoints, timeout, labels))
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
// combines them with internal envoy-provided
func newProxyMetricsHandler(
	exporter *ocprom.Exporter,
	endpoints []ScrapeEndpoint,
	timeout time.Duration,
	labels map[string]string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		if err := writeMetricsMux(ctx, w, append(
			scrapeEndpoints(endpoints, labels),
			ocExport("pomerium", exporter, r, labels)),
		); err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("responding to metrics request")
		}
	}
}

type promProducerResult struct {
	name   string
	src    io.ReadCloser
	labels map[string]string
	err    error
}

// promProducerFn returns a reader containing prometheus-style metrics and additional labels to add to each record
type promProducerFn func(context.Context) promProducerResult

// writeMetricsMux runs producers concurrently and pipes output to destination yet avoiding data interleaving
func writeMetricsMux(ctx context.Context, w io.Writer, producers []promProducerFn) error {
	results := make(chan promProducerResult)
	bw := bufio.NewWriter(w)

	for _, p := range producers {
		go func(fn promProducerFn) {
			results <- fn(ctx)
		}(p)
	}

	var errs *multierror.Error
loop_producers:
	for i := 0; i < len(producers); i++ {
		select {
		case <-ctx.Done():
			err := fmt.Errorf("processed %d metric producers out of %d: %w", i, len(producers), ctx.Err())
			errs = multierror.Append(errs, err, writePrometheusComment(bw, err.Error()))
			break loop_producers
		case res := <-results:
			if err := writeMetricsResult(bw, res); err != nil {
				errs = multierror.Append(errs, fmt.Errorf("%s: %w", res.name, err))
			}
		}
	}
	errs = multierror.Append(errs, bw.Flush())

	return errs.ErrorOrNil()
}

func writeMetricsResult(w io.Writer, res promProducerResult) error {
	if res.err != nil {
		return fmt.Errorf("fetch: %w", res.err)
	}
	return errors.Join(
		prometheus.RelabelTextStream(w, res.src, res.labels),
		res.src.Close(),
	)
}

func writePrometheusComment(w io.Writer, txt string) error {
	lines := strings.Split(txt, "\n")
	for _, line := range lines {
		if _, err := w.Write([]byte(fmt.Sprintf("# %s\n", line))); err != nil {
			return fmt.Errorf("write prometheus comment: %w", err)
		}
	}
	return nil
}

func ocExport(name string, exporter *ocprom.Exporter, r *http.Request, labels map[string]string) promProducerFn {
	return func(context.Context) promProducerResult {
		// Ensure we don't get entangled with compression from ocprom
		r.Header.Del("Accept-Encoding")
		// Request metrics in text format.
		r.Header.Set("Accept", "text/plain")

		rec := httptest.NewRecorder()
		exporter.ServeHTTP(rec, r)

		if rec.Code/100 != 2 {
			return promProducerResult{name: name, err: errors.New(rec.Result().Status)} //nolint
		}

		return promProducerResult{
			name:   name,
			src:    rec.Result().Body, //nolint
			labels: labels,
		}
	}
}

func scrapeEndpoints(endpoints []ScrapeEndpoint, labels map[string]string) []promProducerFn {
	out := make([]promProducerFn, 0, len(endpoints))
	for _, endpoint := range endpoints {
		out = append(out, scrapeEndpoint(endpoint, labels))
	}
	return out
}

func scrapeEndpoint(endpoint ScrapeEndpoint, extra map[string]string) promProducerFn {
	return func(ctx context.Context) promProducerResult {
		name := fmt.Sprintf("%s %s", endpoint.Name, endpoint.URL.String())

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.URL.String(), nil)
		if err != nil {
			return promProducerResult{name: name, err: fmt.Errorf("make request: %w", err)}
		}

		resp, err := http.DefaultClient.Do(req) //nolint
		if err != nil {
			return promProducerResult{name: name, err: fmt.Errorf("request: %w", err)}
		}

		if resp.StatusCode/100 != 2 {
			return promProducerResult{name: name, err: errors.New(resp.Status)}
		}

		labels := make(map[string]string, len(endpoint.Labels)+len(extra))
		maps.Copy(labels, extra)
		maps.Copy(labels, endpoint.Labels)
		return promProducerResult{
			name:   name,
			src:    resp.Body,
			labels: labels,
		}
	}
}
