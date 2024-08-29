package middleware

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/log"
)

// Recovery is an HTTP middleware function that logs any panics.
func Recovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Ctx(r.Context()).Error().Interface("error", err).Msg("middleware: panic while serving http")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
