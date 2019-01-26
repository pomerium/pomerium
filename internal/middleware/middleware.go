package middleware // import "github.com/pomerium/pomerium/internal/middleware"

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/httputil"
)

// SetHeaders ensures that every response includes some basic security headers
func SetHeaders(securityHeaders map[string]string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for key, val := range securityHeaders {
				w.Header().Set(key, val)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ValidateClientSecret checks the request header for the client secret and returns
// an error if it does not match the proxy client secret
func ValidateClientSecret(sharedSecret string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := r.ParseForm()
			if err != nil {
				httputil.ErrorResponse(w, r, err.Error(), http.StatusBadRequest)
				return
			}
			clientSecret := r.Form.Get("shared_secret")
			// check the request header for the client secret
			if clientSecret == "" {
				clientSecret = r.Header.Get("X-Client-Secret")
			}

			if clientSecret != sharedSecret {
				httputil.ErrorResponse(w, r, "Invalid client secret", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ValidateRedirectURI checks the redirect uri in the query parameters and ensures that
// the its domain is in the list of proxy root domains.
func ValidateRedirectURI(proxyRootDomains []string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := r.ParseForm()
			if err != nil {
				httputil.ErrorResponse(w, r, err.Error(), http.StatusBadRequest)
				return
			}
			redirectURI := r.Form.Get("redirect_uri")
			if !ValidRedirectURI(redirectURI, proxyRootDomains) {
				httputil.ErrorResponse(w, r, "Invalid redirect parameter", http.StatusBadRequest)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ValidRedirectURI checks if a URL's domain is one in the list of proxy root domains.
func ValidRedirectURI(uri string, rootDomains []string) bool {
	if uri == "" || len(rootDomains) == 0 {
		return false
	}
	redirectURL, err := url.Parse(uri)
	if err != nil || redirectURL.Host == "" {
		return false
	}
	for _, domain := range rootDomains {
		if domain == "" {
			return false
		}
		if strings.HasSuffix(redirectURL.Hostname(), domain) {
			return true
		}
	}
	return false
}

// ValidateSignature ensures the request is valid and has been signed with
// the correspdoning client secret key
func ValidateSignature(sharedSecret string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := r.ParseForm()
			if err != nil {
				httputil.ErrorResponse(w, r, err.Error(), http.StatusBadRequest)
				return
			}
			redirectURI := r.Form.Get("redirect_uri")
			sigVal := r.Form.Get("sig")
			timestamp := r.Form.Get("ts")
			if !ValidSignature(redirectURI, sigVal, timestamp, sharedSecret) {
				httputil.ErrorResponse(w, r, "Cross service signature failed to validate", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ValidateHost ensures that each request's host is valid
func ValidateHost(mux map[string]http.Handler) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := mux[r.Host]; !ok {
				httputil.ErrorResponse(w, r, "Unknown host to route", http.StatusNotFound)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireHTTPS reroutes a HTTP request to HTTPS
// todo(bdd) : this is unreliable unless behind another reverser proxy
// todo(bdd) : header age seems extreme
func RequireHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		// todo(bdd) : scheme and x-forwarded-proto cannot be trusted if not behind another load balancer
		if (r.URL.Scheme == "http" && r.Header.Get("X-Forwarded-Proto") == "http") || &r.TLS == nil {
			dest := &url.URL{
				Scheme:   "https",
				Host:     r.Host,
				Path:     r.URL.Path,
				RawQuery: r.URL.RawQuery,
			}
			http.Redirect(w, r, dest.String(), http.StatusMovedPermanently)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Healthcheck endpoint middleware useful to setting up a path like
// `/ping` that load balancers or uptime testing external services
// can make a request before hitting any routes. It's also convenient
// to place this above ACL middlewares as well.
func Healthcheck(endpoint, msg string) func(http.Handler) http.Handler {
	f := func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && strings.EqualFold(r.URL.Path, endpoint) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(msg))
				return
			}
			next.ServeHTTP(w, r)
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
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(rawRedirect))
	h.Write([]byte(fmt.Sprint(timestamp.Unix())))
	return h.Sum(nil)
}
