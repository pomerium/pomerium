package telemetry

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/telemetry/metrics"
)

// HTTPStatsRoundTripper creates tracing and metrics RoundTripper for a pomerium service
func HTTPStatsRoundTripper(getInstallationID func() string, service string, destination string) func(next http.RoundTripper) http.RoundTripper {
	return metrics.HTTPMetricsRoundTripper(getInstallationID, ServiceName(service), destination)
}

// HTTPStatsHandler creates tracing and metrics Handler for a pomerium service
func HTTPStatsHandler(getInstallationID func() string, service string) func(next http.Handler) http.Handler {
	return metrics.HTTPMetricsHandler(getInstallationID, ServiceName(service))
}
