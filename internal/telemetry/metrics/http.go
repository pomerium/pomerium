package metrics

import (
	"fmt"
	"net/http"

	"go.opencensus.io/plugin/ochttp"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/tripper"
)

// HTTP Views
var (
	// HTTPClientViews contains opencensus views for HTTP Client metrics.
	HTTPClientViews = []*view.View{
		HTTPClientRequestCountView,
		HTTPClientRequestDurationView,
		HTTPClientResponseSizeView,
	}
	// HTTPServerViews contains opencensus views for HTTP Server metrics.
	HTTPServerViews = []*view.View{
		HTTPServerRequestCountView,
		HTTPServerRequestDurationView,
		HTTPServerRequestSizeView,
		HTTPServerResponseSizeView,
	}

	// HTTPServerRequestCountView is an OpenCensus View that tracks HTTP server
	// requests by pomerium service, host, method and status
	HTTPServerRequestCountView = &view.View{
		Name:        "http/server/requests_total",
		Measure:     ochttp.ServerLatency,
		Description: "Total HTTP Requests",
		TagKeys:     []tag.Key{TagKeyService, TagKeyHost, TagKeyHTTPMethod, ochttp.StatusCode},
		Aggregation: view.Count(),
	}

	// HTTPServerRequestDurationView is an OpenCensus view that tracks HTTP
	// server request duration by pomerium service, host, method and status
	HTTPServerRequestDurationView = &view.View{
		Name:        "http/server/request_duration_ms",
		Measure:     ochttp.ServerLatency,
		Description: "HTTP Request duration in ms",
		TagKeys:     []tag.Key{TagKeyService, TagKeyHost, TagKeyHTTPMethod, ochttp.StatusCode},
		Aggregation: DefaultHTTPLatencyDistrubtion,
	}

	// HTTPServerRequestSizeView is an OpenCensus view that tracks HTTP server
	// request size by pomerium service, host and method
	HTTPServerRequestSizeView = &view.View{
		Name:        "http/server/request_size_bytes",
		Measure:     ochttp.ServerRequestBytes,
		Description: "HTTP Server Request Size in bytes",
		TagKeys:     []tag.Key{TagKeyService, TagKeyHost, TagKeyHTTPMethod},
		Aggregation: DefaulHTTPSizeDistribution,
	}

	// HTTPServerResponseSizeView is an OpenCensus view that tracks HTTP server
	// response size by pomerium service, host, method and status
	HTTPServerResponseSizeView = &view.View{
		Name:        "http/server/response_size_bytes",
		Measure:     ochttp.ServerResponseBytes,
		Description: "HTTP Server Response Size in bytes",
		TagKeys:     []tag.Key{TagKeyService, TagKeyHost, TagKeyHTTPMethod, ochttp.StatusCode},
		Aggregation: DefaulHTTPSizeDistribution,
	}

	// HTTPClientRequestCountView is an OpenCensus View that tracks HTTP client
	// requests by pomerium service, destination, host, method and status
	HTTPClientRequestCountView = &view.View{
		Name:        "http/client/requests_total",
		Measure:     ochttp.ClientRoundtripLatency,
		Description: "Total HTTP Client Requests",
		TagKeys:     []tag.Key{TagKeyService, TagKeyHost, TagKeyHTTPMethod, ochttp.StatusCode},
		Aggregation: view.Count(),
	}

	// HTTPClientRequestDurationView is an OpenCensus view that tracks HTTP
	// client request duration by pomerium service, destination, host, method and status
	HTTPClientRequestDurationView = &view.View{
		Name:        "http/client/request_duration_ms",
		Measure:     ochttp.ClientRoundtripLatency,
		Description: "HTTP Client Request duration in ms",
		TagKeys:     []tag.Key{TagKeyService, TagKeyHost, TagKeyHTTPMethod, ochttp.StatusCode},
		Aggregation: DefaultHTTPLatencyDistrubtion,
	}

	// HTTPClientResponseSizeView is an OpenCensus view that tracks HTTP client
	// esponse size by pomerium service, destination, host, method and status
	HTTPClientResponseSizeView = &view.View{
		Name:        "http/client/response_size_bytes",
		Measure:     ochttp.ClientReceivedBytes,
		Description: "HTTP Client Response Size in bytes",
		TagKeys:     []tag.Key{TagKeyService, TagKeyHost, TagKeyHTTPMethod, ochttp.StatusCode},
		Aggregation: DefaulHTTPSizeDistribution,
	}

	// HTTPClientRequestSizeView is an OpenCensus view that tracks HTTP client
	// request size by pomerium service, destination, host and method
	HTTPClientRequestSizeView = &view.View{
		Name:        "http/client/response_size_bytes",
		Measure:     ochttp.ClientSentBytes,
		Description: "HTTP Client Response Size in bytes",
		TagKeys:     []tag.Key{TagKeyService, TagKeyHost, TagKeyHTTPMethod},
		Aggregation: DefaulHTTPSizeDistribution,
	}
)

// HTTPMetricsHandler creates a metrics middleware for incoming HTTP requests
func HTTPMetricsHandler(_ func() string, service string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, tagErr := tag.New(
				r.Context(),
				tag.Upsert(TagKeyService, service),
				tag.Upsert(TagKeyHost, r.Host),
				tag.Upsert(TagKeyHTTPMethod, r.Method),
			)
			if tagErr != nil {
				log.Ctx(ctx).Error().Err(tagErr).Str("context", "HTTPMetricsHandler").Msg("telemetry/metrics: failed to create metrics tag")
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
func HTTPMetricsRoundTripper(_ func() string, service string) func(next http.RoundTripper) http.RoundTripper {
	return func(next http.RoundTripper) http.RoundTripper {
		return tripper.RoundTripperFunc(func(r *http.Request) (*http.Response, error) {
			ctx, tagErr := tag.New(
				r.Context(),
				tag.Upsert(TagKeyService, service),
				tag.Upsert(TagKeyHost, r.Host),
				tag.Upsert(TagKeyHTTPMethod, r.Method),
			)
			if tagErr != nil {
				log.Ctx(ctx).Error().Err(tagErr).Str("context", "HTTPMetricsRoundTripper").Msg("telemetry/metrics: failed to create metrics tag")
				return next.RoundTrip(r)
			}

			ocTransport := ochttp.Transport{Base: next}
			return ocTransport.RoundTrip(r.WithContext(ctx))
		})
	}
}
