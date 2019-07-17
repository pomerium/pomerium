package telemetry // import "github.com/pomerium/pomerium/internal/telemetry"

import (
	"fmt"
	"net/http"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/tripper"

	"go.opencensus.io/plugin/ochttp"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
)

var (
	httpSizeDistribution = view.Distribution(
		1, 256, 512, 1024, 2048, 8192, 16384, 32768, 65536, 131072, 262144, 524288,
		1048576, 2097152, 4194304, 8388608,
	)

	httpLatencyDistrubtion = view.Distribution(
		1, 2, 5, 7, 10, 25, 500, 750,
		100, 250, 500, 750,
		1000, 2500, 5000, 7500,
		10000, 25000, 50000, 75000,
		100000,
	)

	// httpClientRequestCount    = stats.Int64("http_client_requests_total", "Total HTTP Client Requests", "1")
	// httpClientResponseSize    = stats.Int64("http_client_response_size_bytes", "HTTP Client Response Size in bytes", "bytes")
	// httpClientRequestDuration = stats.Int64("http_client_request_duration_ms", "HTTP Client Request duration in ms", "ms")

	// HTTPServerRequestCountView is an OpenCensus View that tracks HTTP server requests by pomerium service, host, method and status
	HTTPServerRequestCountView = &view.View{
		Name:        "http_server_requests_total",
		Measure:     ochttp.ServerLatency,
		Description: "Total HTTP Requests",
		TagKeys:     []tag.Key{keyService, keyHost, keyHTTPMethod, ochttp.StatusCode},
		Aggregation: view.Count(),
	}

	// HTTPServerRequestDurationView is an OpenCensus view that tracks HTTP server request duration by pomerium service, host, method and status
	HTTPServerRequestDurationView = &view.View{
		Name:        "http_server_request_duration_ms",
		Measure:     ochttp.ServerLatency,
		Description: "HTTP Request duration in ms",
		TagKeys:     []tag.Key{keyService, keyHost, keyHTTPMethod, ochttp.StatusCode},
		Aggregation: httpLatencyDistrubtion,
	}

	// HTTPServerRequestSizeView is an OpenCensus view that tracks HTTP server request size by pomerium service, host and method
	HTTPServerRequestSizeView = &view.View{
		Name:        "http_server_request_size_bytes",
		Measure:     ochttp.ServerRequestBytes,
		Description: "HTTP Server Request Size in bytes",
		TagKeys:     []tag.Key{keyService, keyHost, keyHTTPMethod},
		Aggregation: httpSizeDistribution,
	}

	// HTTPServerResponseSizeView is an OpenCensus view that tracks HTTP server response size by pomerium service, host, method and status
	HTTPServerResponseSizeView = &view.View{
		Name:        "http_server_response_size_bytes",
		Measure:     ochttp.ServerResponseBytes,
		Description: "HTTP Server Response Size in bytes",
		TagKeys:     []tag.Key{keyService, keyHost, keyHTTPMethod, ochttp.StatusCode},
		Aggregation: httpSizeDistribution,
	}

	// HTTPClientRequestCountView is an OpenCensus View that tracks HTTP client requests by pomerium service, destination, host, method and status
	HTTPClientRequestCountView = &view.View{
		Name:        "http_client_requests_total",
		Measure:     ochttp.ClientRoundtripLatency,
		Description: "Total HTTP Client Requests",
		TagKeys:     []tag.Key{keyService, keyHost, keyHTTPMethod, ochttp.StatusCode, keyDestination},
		Aggregation: view.Count(),
	}

	// HTTPClientRequestDurationView is an OpenCensus view that tracks HTTP client request duration by pomerium service, destination, host, method and status
	HTTPClientRequestDurationView = &view.View{
		Name:        "http_client_request_duration_ms",
		Measure:     ochttp.ClientRoundtripLatency,
		Description: "HTTP Client Request duration in ms",
		TagKeys:     []tag.Key{keyService, keyHost, keyHTTPMethod, ochttp.StatusCode, keyDestination},
		Aggregation: httpLatencyDistrubtion,
	}

	// HTTPClientResponseSizeView is an OpenCensus view that tracks HTTP client response size by pomerium service, destination, host, method and status
	HTTPClientResponseSizeView = &view.View{
		Name:        "http_client_response_size_bytes",
		Measure:     ochttp.ClientReceivedBytes,
		Description: "HTTP Client Response Size in bytes",
		TagKeys:     []tag.Key{keyService, keyHost, keyHTTPMethod, ochttp.StatusCode, keyDestination},
		Aggregation: httpSizeDistribution,
	}

	// HTTPClientRequestSizeView is an OpenCensus view that tracks HTTP client request size by pomerium service, destination, host and method
	HTTPClientRequestSizeView = &view.View{
		Name:        "http_client_response_size_bytes",
		Measure:     ochttp.ClientSentBytes,
		Description: "HTTP Client Response Size in bytes",
		TagKeys:     []tag.Key{keyService, keyHost, keyHTTPMethod, keyDestination},
		Aggregation: httpSizeDistribution,
	}
)

// HTTPMetricsHandler creates a metrics middleware for incoming HTTP requests
func HTTPMetricsHandler(service string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, tagErr := tag.New(
				r.Context(),
				tag.Insert(keyService, service),
				tag.Insert(keyHost, r.Host),
				tag.Insert(keyHTTPMethod, r.Method),
			)
			if tagErr != nil {
				log.Warn().Err(tagErr).Str("context", "HTTPMetricsHandler").Msg("internal/telemetry: failed to create metrics tag")
				next.ServeHTTP(w, r)
				return
			}

			ocHandler := ochttp.Handler{
				Handler: next,
				FormatSpanName: func(r *http.Request) string {
					return fmt.Sprintf("%s%s", r.Host, r.URL.Path)
				},
			}
			ocHandler.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// HTTPMetricsRoundTripper creates a metrics tracking tripper for outbound HTTP Requests
func HTTPMetricsRoundTripper(service string, destination string) func(next http.RoundTripper) http.RoundTripper {
	return func(next http.RoundTripper) http.RoundTripper {
		return tripper.RoundTripperFunc(func(r *http.Request) (*http.Response, error) {

			ctx, tagErr := tag.New(
				r.Context(),
				tag.Insert(keyService, service),
				tag.Insert(keyHost, r.Host),
				tag.Insert(keyHTTPMethod, r.Method),
				tag.Insert(keyDestination, destination),
			)

			if tagErr != nil {
				log.Warn().Err(tagErr).Str("context", "HTTPMetricsRoundTripper").Msg("internal/telemetry: failed to create metrics tag")
				return next.RoundTrip(r)
			}

			ocTransport := ochttp.Transport{Base: next}
			return ocTransport.RoundTrip(r.WithContext(ctx))
		})
	}
}
