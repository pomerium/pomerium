package middleware // import "github.com/pomerium/pomerium/internal/middleware"

import (
	"crypto/hmac"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/telemetry/trace"

	"golang.org/x/net/publicsuffix"
)

// SetHeaders ensures that every response includes some basic security headers
func SetHeaders(securityHeaders map[string]string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := trace.StartSpan(r.Context(), "middleware.SetHeaders")
			defer span.End()
			for key, val := range securityHeaders {
				w.Header().Set(key, val)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ValidateClientSecret checks the request header for the client secret and returns
// an error if it does not match the proxy client secret
func ValidateClientSecret(sharedSecret string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := trace.StartSpan(r.Context(), "middleware.ValidateClientSecret")
			defer span.End()

			if err := r.ParseForm(); err != nil {
				httputil.ErrorResponse(w, r, httputil.WrappedHTTPError("couldn't parse form", http.StatusBadRequest, err))
				return
			}
			clientSecret := r.Form.Get("shared_secret")
			// check the request header for the client secret
			if clientSecret == "" {
				clientSecret = r.Header.Get("X-Client-Secret")
			}

			if clientSecret != sharedSecret {
				httputil.ErrorResponse(w, r, httputil.NewHTTPError("client secret mismatch", http.StatusBadRequest))
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ValidateRedirectURI checks the redirect uri in the query parameters and ensures that
// the its domain is in the list of proxy root domains.
func ValidateRedirectURI(rootDomain *url.URL) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := trace.StartSpan(r.Context(), "middleware.ValidateRedirectURI")
			defer span.End()
			err := r.ParseForm()
			if err != nil {
				httputil.ErrorResponse(w, r, httputil.WrappedHTTPError("couldn't parse form", http.StatusBadRequest, err))
				return
			}
			redirectURI, err := url.Parse(r.Form.Get("redirect_uri"))
			if err != nil {
				httputil.ErrorResponse(w, r, httputil.WrappedHTTPError("bad redirect_uri", http.StatusBadRequest, err))
				return
			}
			if !SameDomain(redirectURI, rootDomain) {
				httputil.ErrorResponse(w, r, httputil.NewHTTPError("redirect uri and root domain differ", http.StatusBadRequest))
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// SameDomain checks to see if two URLs share the top level domain (TLD Plus One).
func SameDomain(u, j *url.URL) bool {
	a, err := publicsuffix.EffectiveTLDPlusOne(u.Hostname())
	if err != nil {
		return false
	}
	b, err := publicsuffix.EffectiveTLDPlusOne(j.Hostname())
	if err != nil {
		return false
	}
	return a == b
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
				httputil.ErrorResponse(w, r, httputil.WrappedHTTPError("couldn't parse form", http.StatusBadRequest, err))
				return
			}
			redirectURI := r.Form.Get("redirect_uri")
			sigVal := r.Form.Get("sig")
			timestamp := r.Form.Get("ts")
			if !ValidSignature(redirectURI, sigVal, timestamp, sharedSecret) {
				httputil.ErrorResponse(w, r, httputil.NewHTTPError("invalid signature", http.StatusBadRequest))
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ValidateHost ensures that each request's host is valid
func ValidateHost(validHost func(host string) bool) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := trace.StartSpan(r.Context(), "middleware.ValidateHost")
			defer span.End()

			if !validHost(r.Host) {
				httputil.ErrorResponse(w, r, httputil.NewHTTPError(fmt.Sprintf("No known route for %s", r.Host), http.StatusNotFound))
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

			if r.Method == "GET" && strings.EqualFold(r.URL.Path, endpoint) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(msg))
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
	_, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}
	requestSig, err := base64.URLEncoding.DecodeString(sigVal)
	if err != nil {
		return false
	}
	i, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	tm := time.Unix(i, 0)
	ttl := 5 * time.Minute
	if time.Since(tm) > ttl {
		return false
	}
	localSig := redirectURLSignature(redirectURI, tm, secret)

	return hmac.Equal(requestSig, localSig)
}

func redirectURLSignature(rawRedirect string, timestamp time.Time, secret string) []byte {
	data := []byte(fmt.Sprint(rawRedirect, timestamp.Unix()))
	h := cryptutil.Hash(secret, data)
	return h
}
