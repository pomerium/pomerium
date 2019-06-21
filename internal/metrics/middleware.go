package metrics // import "github.com/pomerium/pomerium/internal/metrics"

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/pomerium/pomerium/internal/log"

	"github.com/pomerium/pomerium/internal/middleware/responsewriter"
	"github.com/pomerium/pomerium/internal/tripper"
	"go.opencensus.io/stats"
	"go.opencensus.io/stats/view"
	"go.opencensus.io/tag"
)

var (
	httpServerRequestCount    = stats.Int64("http_server_requests_total", "Total HTTP Requests", "1")
	httpServerResponseSize    = stats.Int64("http_server_response_size_bytes", "HTTP Server Response Size in bytes", "bytes")
	httpServerRequestDuration = stats.Int64("http_server_request_duration_ms", "HTTP Request duration in ms", "ms")

	httpClientRequestCount    = stats.Int64("http_client_requests_total", "Total HTTP Client Requests", "1")
	httpClientResponseSize    = stats.Int64("http_client_response_size_bytes", "HTTP Client Response Size in bytes", "bytes")
	httpClientRequestDuration = stats.Int64("http_client_request_duration_ms", "HTTP Client Request duration in ms", "ms")

	views = []*view.View{
		//HTTP Server
		{
			Name:        httpServerRequestCount.Name(),
			Measure:     httpServerRequestCount,
			Description: httpServerRequestCount.Description(),
			TagKeys:     []tag.Key{keyService, keyHost, keyMethod, keyStatus},
			Aggregation: view.Count(),
		},
		{
			Name:        httpServerRequestDuration.Name(),
			Measure:     httpServerRequestDuration,
			Description: httpServerRequestDuration.Description(),
			TagKeys:     []tag.Key{keyService, keyHost, keyMethod, keyStatus},
			Aggregation: view.Distribution(
				1, 2, 5, 7, 10, 25, 500, 750,
				100, 250, 500, 750,
				1000, 2500, 5000, 7500,
				10000, 25000, 50000, 75000,
				100000,
			),
		},
		{
			Name:        httpServerResponseSize.Name(),
			Measure:     httpServerResponseSize,
			Description: httpServerResponseSize.Description(),
			TagKeys:     []tag.Key{keyService, keyHost, keyMethod, keyStatus},
			Aggregation: view.Distribution(
				1, 256, 512, 1024, 2048, 8192, 16384, 32768, 65536, 131072, 262144, 524288,
				1048576, 2097152, 4194304, 8388608,
			),
		},

		//HTTP Client
		{
			Name:        httpClientRequestCount.Name(),
			Measure:     httpClientRequestCount,
			Description: httpClientRequestCount.Description(),
			TagKeys:     []tag.Key{keyService, keyHost, keyMethod, keyStatus},
			Aggregation: view.Count(),
		},
		{
			Name:        httpClientRequestDuration.Name(),
			Measure:     httpClientRequestDuration,
			Description: httpClientRequestDuration.Description(),
			TagKeys:     []tag.Key{keyService, keyHost, keyMethod, keyStatus},
			Aggregation: view.Distribution(
				1, 2, 5, 7, 10, 25, 500, 750,
				100, 250, 500, 750,
				1000, 2500, 5000, 7500,
				10000, 25000, 50000, 75000,
				100000,
			),
		},
		{
			Name:        httpClientResponseSize.Name(),
			Measure:     httpClientResponseSize,
			Description: httpClientResponseSize.Description(),
			TagKeys:     []tag.Key{keyService, keyHost, keyMethod, keyStatus},
			Aggregation: view.Distribution(
				1, 256, 512, 1024, 2048, 8192, 16384, 32768, 65536, 131072, 262144, 524288,
				1048576, 2097152, 4194304, 8388608,
			),
		},
	}
)

func init() {
	view.Register(views...)
}

// HTTPMetricsHandler creates a metrics middleware for incoming HTTP requests
func HTTPMetricsHandler(service string) func(next http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			startTime := time.Now()
			m := responsewriter.NewWrapResponseWriter(w, 1)

			next.ServeHTTP(m, r)

			ctx, tagErr := tag.New(
				context.Background(),
				tag.Insert(keyService, service),
				tag.Insert(keyHost, r.Host),
				tag.Insert(keyMethod, r.Method),
				tag.Insert(keyStatus, strconv.Itoa(m.Status())),
			)

			if tagErr != nil {
				log.Warn().Err(tagErr).Str("context", "HTTPMetricsHandler").Msg("Failed to create metrics context tag")
			} else {
				stats.Record(ctx,
					httpServerRequestCount.M(1),
					httpServerRequestDuration.M(time.Since(startTime).Nanoseconds()/int64(time.Millisecond)),
					httpServerResponseSize.M(int64(m.BytesWritten())),
				)
			}
		})
	}
}

// HTTPMetricsRoundTripper creates a metrics tracking tripper for outbound HTTP Requests
func HTTPMetricsRoundTripper(service string) func(next http.RoundTripper) http.RoundTripper {

	return func(next http.RoundTripper) http.RoundTripper {
		return tripper.RoundTripperFunc(func(r *http.Request) (*http.Response, error) {
			startTime := time.Now()

			resp, err := next.RoundTrip(r)

			if resp != nil && err == nil {
				ctx, tagErr := tag.New(
					context.Background(),
					tag.Insert(keyService, service),
					tag.Insert(keyHost, r.Host),
					tag.Insert(keyMethod, r.Method),
					tag.Insert(keyStatus, strconv.Itoa(resp.StatusCode)),
				)

				if tagErr != nil {
					log.Warn().Err(tagErr).Str("context", "HTTPMetricsRoundTripper").Msg("Failed to create context tag")
				} else {
					stats.Record(ctx,
						httpClientRequestCount.M(1),
						httpClientRequestDuration.M(time.Since(startTime).Nanoseconds()/int64(time.Millisecond)),
						httpClientResponseSize.M(resp.ContentLength),
					)
				}
			}
			return resp, err
		})
	}
}
