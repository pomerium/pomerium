package middleware // import "github.com/pomerium/pomerium/internal/middleware"

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
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
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := trace.StartSpan(r.Context(), "middleware.ValidateSignature")
			defer span.End()

			err := r.ParseForm()
			if err != nil {
				httputil.ErrorResponse(w, r, httputil.Error("couldn't parse form", http.StatusBadRequest, err))
				return
			}
			redirectURI := r.Form.Get("redirect_uri")
			sigVal := r.Form.Get("sig")
			timestamp := r.Form.Get("ts")
			if !ValidSignature(redirectURI, sigVal, timestamp, sharedSecret) {
				httputil.ErrorResponse(w, r, httputil.Error("invalid signature", http.StatusBadRequest, nil))
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Healthcheck endpoint middleware useful to setting up a path like
// `/ping` that load balancers or uptime testing external services
// can make a request before hitting any routes. It's also convenient
// to place this above ACL middlewares as well.
func Healthcheck(endpoint, msg string) func(http.Handler) http.Handler {
	f := func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx, span := trace.StartSpan(r.Context(), "middleware.Healthcheck")
			defer span.End()
			if strings.EqualFold(r.URL.Path, endpoint) {
				// https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html
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

// ValidSignature checks to see if a signature is valid. Compares hmac of
// redirect uri, timestamp, and secret and signature.
func ValidSignature(redirectURI, sigVal, timestamp, secret string) bool {
	if redirectURI == "" || sigVal == "" || timestamp == "" || secret == "" {
		return false
	}
	_, err := urlutil.ParseAndValidateURL(redirectURI)
	if err != nil {
		return false
	}
	requestSig, err := base64.URLEncoding.DecodeString(sigVal)
	if err != nil {
		return false
	}
	if err := cryptutil.ValidTimestamp(timestamp); err != nil {
		return false
	}
	return cryptutil.CheckHMAC([]byte(fmt.Sprint(redirectURI, timestamp)), requestSig, secret)
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
