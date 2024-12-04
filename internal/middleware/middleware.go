package middleware

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// SetHeaders sets a map of response headers.
func SetHeaders(headers map[string]string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := trace.Continue(r.Context(), "middleware.SetHeaders")
			defer span.End()
			for key, val := range headers {
				w.Header().Set(key, val)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ValidateSignature ensures the request is valid and has been signed with
// the corresponding client secret key
func ValidateSignature(sharedKey []byte) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			ctx, span := trace.Continue(r.Context(), "middleware.ValidateSignature")
			defer span.End()
			if err := ValidateRequestURL(r, sharedKey); err != nil {
				return httputil.NewError(http.StatusBadRequest, err)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
			return nil
		})
	}
}

// ValidateRequestURL validates the current absolute request URL was signed
// by a given shared key.
func ValidateRequestURL(r *http.Request, key []byte) error {
	return urlutil.NewSignedURL(key, urlutil.GetAbsoluteURL(r)).Validate()
}

// RequireBasicAuth creates a new handler that requires basic auth from the client before
// calling the underlying handler.
func RequireBasicAuth(username, password string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, p, ok := r.BasicAuth()
			if !ok {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			givenUser := sha256.Sum256([]byte(u))
			givenPass := sha256.Sum256([]byte(p))
			requiredUser := sha256.Sum256([]byte(username))
			requiredPass := sha256.Sum256([]byte(password))

			if subtle.ConstantTimeCompare(givenUser[:], requiredUser[:]) != 1 ||
				subtle.ConstantTimeCompare(givenPass[:], requiredPass[:]) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
