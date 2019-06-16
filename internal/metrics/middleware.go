package metrics

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/pomerium/pomerium/internal/middleware/responsewriter"

	"go.opencensus.io/tag"

	"go.opencensus.io/stats/view"

	"go.opencensus.io/stats"
)

var (
	keyMethod, _  = tag.NewKey("method")
	keyStatus, _  = tag.NewKey("status")
	keyService, _ = tag.NewKey("service")
	keyHost, _    = tag.NewKey("host")

	httpRequestCount    = stats.Int64("http_server_requests_total", "Total HTTP Requests", "1")
	httpResponseSize    = stats.Int64("http_server_response_size_bytes", "HTTP Server Response Size in bytes", "bytes")
	httpRequestDuration = stats.Int64("http_server_request_duration_ms", "HTTP Request duration in ms", "ms")

	views = []*view.View{
		&view.View{
			Name:        httpRequestCount.Name(),
			Measure:     httpRequestCount,
			Description: httpRequestCount.Description(),
			TagKeys:     []tag.Key{keyService, keyHost, keyMethod, keyStatus},
			Aggregation: view.Count(),
		},
		&view.View{
			Name:        httpRequestDuration.Name(),
			Measure:     httpRequestDuration,
			Description: httpRequestDuration.Description(),
			TagKeys:     []tag.Key{keyService, keyHost, keyMethod, keyStatus},
			Aggregation: view.Distribution(
				1, 2, 5, 7, 10, 25, 500, 750,
				100, 250, 500, 750,
				1000, 2500, 5000, 7500,
				10000, 25000, 50000, 75000,
				100000,
			),
		},
		&view.View{
			Name:        httpResponseSize.Name(),
			Measure:     httpResponseSize,
			Description: httpResponseSize.Description(),
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

			ctx, _ := tag.New(
				context.Background(),
				tag.Insert(keyService, service),
				tag.Insert(keyHost, r.Host),
				tag.Insert(keyMethod, r.Method),
				tag.Insert(keyStatus, strconv.Itoa(m.Status())),
			)
			stats.Record(ctx,
				httpRequestCount.M(1),
				httpRequestDuration.M(time.Since(startTime).Nanoseconds()/int64(time.Millisecond)),
				httpResponseSize.M(int64(m.BytesWritten())),
			)
		})
	}
}
