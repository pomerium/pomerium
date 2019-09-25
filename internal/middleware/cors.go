package middleware // import "github.com/pomerium/pomerium/internal/middleware"

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/telemetry/trace"
)

// CorsBypass is middleware that takes a target handler as a paramater,
// if the request is determined to be a CORS preflight request, that handler
// is called instead of the normal handler chain.
func CorsBypass(target http.Handler) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := trace.StartSpan(r.Context(), "middleware.CorsBypass")
			defer span.End()
			if r.Method == http.MethodOptions &&
				r.Header.Get("Access-Control-Request-Method") != "" &&
				r.Header.Get("Origin") != "" {
				target.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
