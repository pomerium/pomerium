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

	"golang.org/x/net/publicsuffix"
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
			if err := r.ParseForm(); err != nil {
				httpErr := &httputil.Error{Message: err.Error(), Code: http.StatusBadRequest}
				httputil.ErrorResponse(w, r, httpErr)
				return
			}
			clientSecret := r.Form.Get("shared_secret")
			// check the request header for the client secret
			if clientSecret == "" {
				clientSecret = r.Header.Get("X-Client-Secret")
			}

			if clientSecret != sharedSecret {
				httputil.ErrorResponse(w, r, &httputil.Error{Code: http.StatusInternalServerError})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ValidateRedirectURI checks the redirect uri in the query parameters and ensures that
// the its domain is in the list of proxy root domains.
func ValidateRedirectURI(rootDomain *url.URL) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			err := r.ParseForm()
			if err != nil {
				httpErr := &httputil.Error{
					Message: err.Error(),
					Code:    http.StatusBadRequest}
				httputil.ErrorResponse(w, r, httpErr)
				return
			}
			redirectURI, err := url.Parse(r.Form.Get("redirect_uri"))
			if err != nil {
				httpErr := &httputil.Error{
					Message: err.Error(),
					Code:    http.StatusBadRequest}
				httputil.ErrorResponse(w, r, httpErr)
				return
			}
			if !SameDomain(redirectURI, rootDomain) {
				httpErr := &httputil.Error{
					Message: "Invalid redirect parameter",
					Code:    http.StatusBadRequest}
				httputil.ErrorResponse(w, r, httpErr)
				return
			}
			next.ServeHTTP(w, r)
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
			err := r.ParseForm()
			if err != nil {
				httpErr := &httputil.Error{Message: err.Error(), Code: http.StatusBadRequest}
				httputil.ErrorResponse(w, r, httpErr)
				return
			}
			redirectURI := r.Form.Get("redirect_uri")
			sigVal := r.Form.Get("sig")
			timestamp := r.Form.Get("ts")
			if !ValidSignature(redirectURI, sigVal, timestamp, sharedSecret) {
				httpErr := &httputil.Error{
					Message: "Cross service signature failed to validate",
					Code:    http.StatusUnauthorized}
				httputil.ErrorResponse(w, r, httpErr)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ValidateHost ensures that each request's host is valid
func ValidateHost(validHost func(host string) bool) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !validHost(r.Host) {
				httputil.ErrorResponse(w, r, &httputil.Error{Code: http.StatusNotFound})
				return
			}
			next.ServeHTTP(w, r)
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
	data := []byte(fmt.Sprint(rawRedirect, timestamp.Unix()))
	h := cryptutil.Hash(secret, data)
	return h
}
