package middleware // import "github.com/pomerium/pomerium/internal/middleware"

import (
	"fmt"
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
				return httputil.NewError(http.StatusBadRequest, fmt.Errorf("invalid signature: %w", err))
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

// Healthcheck endpoint middleware useful to setting up a path like
// `/ping` that load balancers or uptime testing external services
// can make a request before hitting any routes. It's also convenient
// to place this above ACL middlewares as well.
//
// https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html
func Healthcheck(endpoint, msg string) func(http.Handler) http.Handler {
	f := func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx, span := trace.StartSpan(r.Context(), "middleware.Healthcheck")
			defer span.End()
			if strings.EqualFold(r.URL.Path, endpoint) {
				if r.Method != http.MethodGet && r.Method != http.MethodHead {
					http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
					return
				}
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				if r.Method == http.MethodGet {
					w.Write([]byte(msg))
				}
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
	return f
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
