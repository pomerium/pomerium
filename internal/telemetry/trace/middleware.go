package trace

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

func NewHTTPMiddleware(opts ...otelhttp.Option) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			routeStr := ""
			route := mux.CurrentRoute(r)
			if route != nil {
				var err error
				routeStr, err = route.GetPathTemplate()
				if err != nil {
					routeStr, err = route.GetPathRegexp()
					if err != nil {
						routeStr = ""
					}
				}
			}
			traceparent := r.Header.Get("Traceparent")
			if traceparent != "" {
				xPomeriumTraceparent := r.Header.Get("X-Pomerium-Traceparent")
				if xPomeriumTraceparent != "" {
					sc, err := ParseTraceparent(xPomeriumTraceparent)
					if err == nil {
						r.Header.Set("Traceparent", ReplaceTraceID(traceparent, sc.TraceID()))
						ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
						r = r.WithContext(ctx)
					}
				}
			}
			otelhttp.NewHandler(next, fmt.Sprintf("Server: %s %s", r.Method, routeStr), opts...).ServeHTTP(w, r)
		})
	}
}
