package middleware // import "github.com/pomerium/pomerium/internal/middleware"

import (
	"net/http"
	"strings"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
)

func SignRequest(signer cryptutil.JWTSigner, id, email, groups, header string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, span := telemetry.StartSpan(r.Context(), "middleware.SignRequest")
			defer span.End()
			jwt, err := signer.SignJWT(
				r.Header.Get(id),
				r.Header.Get(email),
				r.Header.Get(groups))
			if err != nil {
				log.Warn().Err(err).Msg("internal/middleware: failed signing request")
			} else {
				r.Header.Set(header, jwt)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// StripPomeriumCookie ensures that every response includes some basic security headers
func StripPomeriumCookie(cookieName string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, span := telemetry.StartSpan(r.Context(), "middleware.StripPomeriumCookie")
			defer span.End()

			headers := make([]string, len(r.Cookies()))
			for _, cookie := range r.Cookies() {
				if cookie.Name != cookieName {
					headers = append(headers, cookie.String())
				}
			}
			r.Header.Set("Cookie", strings.Join(headers, ";"))
			next.ServeHTTP(w, r)
		})
	}
}
