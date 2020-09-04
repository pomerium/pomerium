package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// SetHeaders sets a map of response headers.
func SetHeaders(headers map[string]string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := trace.StartSpan(r.Context(), "middleware.SetHeaders")
			defer span.End()
			for key, val := range headers {
				w.Header().Set(key, val)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ValidateSignature ensures the request is valid and has been signed with
// the correspdoning client secret key
func ValidateSignature(sharedSecret string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			ctx, span := trace.StartSpan(r.Context(), "middleware.ValidateSignature")
			defer span.End()
			if err := ValidateRequestURL(r, sharedSecret); err != nil {
				return httputil.NewError(http.StatusBadRequest, err)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
			return nil
		})
	}
}

// ValidateRequestURL validates the current absolute request URL was signed
// by a given shared key.
func ValidateRequestURL(r *http.Request, key string) error {
	return urlutil.NewSignedURL(key, urlutil.GetAbsoluteURL(r)).Validate()
}

// StripCookie strips the cookie from the downstram request.
func StripCookie(cookieName string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := trace.StartSpan(r.Context(), "middleware.StripCookie")
			defer span.End()

			headers := make([]string, 0, len(r.Cookies()))
			for _, cookie := range r.Cookies() {
				if !strings.HasPrefix(cookie.Name, cookieName) {
					headers = append(headers, cookie.String())
				}
			}
			r.Header.Set("Cookie", strings.Join(headers, ";"))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// TimeoutHandlerFunc wraps http.TimeoutHandler
func TimeoutHandlerFunc(timeout time.Duration, timeoutError string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := trace.StartSpan(r.Context(), "middleware.TimeoutHandlerFunc")
			defer span.End()
			http.TimeoutHandler(next, timeout, timeoutError).ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
