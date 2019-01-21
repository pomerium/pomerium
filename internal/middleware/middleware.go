// Package middleware provides a standard set of middleware implementations for pomerium.
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

// SetHeadersOld ensures that every response includes some basic security headers
func SetHeadersOld(h http.Handler, securityHeaders map[string]string) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		for key, val := range securityHeaders {
			rw.Header().Set(key, val)
		}
		h.ServeHTTP(rw, req)
	})
}

// SetHeaders ensures that every response includes some basic security headers
func SetHeaders(securityHeaders map[string]string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			for key, val := range securityHeaders {
				rw.Header().Set(key, val)
			}
			next.ServeHTTP(rw, req)
		})
	}
}

// WithMethods writes an error response if the method of the request is not included.
func WithMethods(f http.HandlerFunc, methods ...string) http.HandlerFunc {
	methodMap := make(map[string]struct{}, len(methods))
	for _, m := range methods {
		methodMap[m] = struct{}{}
	}
	return func(rw http.ResponseWriter, req *http.Request) {
		if _, ok := methodMap[req.Method]; !ok {
			httputil.ErrorResponse(rw, req, fmt.Sprintf("method %s not allowed", req.Method), http.StatusMethodNotAllowed)
			return
		}
		f(rw, req)
	}
}

// ValidateClientSecret checks the request header for the client secret and returns
// an error if it does not match the proxy client secret
func ValidateClientSecret(f http.HandlerFunc, sharedSecret string) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		err := req.ParseForm()
		if err != nil {
			httputil.ErrorResponse(rw, req, err.Error(), http.StatusInternalServerError)
			return
		}
		clientSecret := req.Form.Get("shared_secret")
		// check the request header for the client secret
		if clientSecret == "" {
			clientSecret = req.Header.Get("X-Client-Secret")
		}

		if clientSecret != sharedSecret {
			httputil.ErrorResponse(rw, req, "Invalid client secret", http.StatusUnauthorized)
			return
		}
		f(rw, req)
	}
}

// ValidateRedirectURI checks the redirect uri in the query parameters and ensures that
// the url's domain is one in the list of proxy root domains.
func ValidateRedirectURI(f http.HandlerFunc, proxyRootDomains []string) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		err := req.ParseForm()
		if err != nil {
			httputil.ErrorResponse(rw, req, err.Error(), http.StatusBadRequest)
			return
		}
		redirectURI := req.Form.Get("redirect_uri")
		if !validRedirectURI(redirectURI, proxyRootDomains) {
			httputil.ErrorResponse(rw, req, "Invalid redirect parameter", http.StatusBadRequest)
			return
		}

		f(rw, req)
	}
}

func validRedirectURI(uri string, rootDomains []string) bool {
	redirectURL, err := url.Parse(uri)
	if uri == "" || err != nil || redirectURL.Host == "" {
		return false
	}
	for _, domain := range rootDomains {
		if strings.HasSuffix(redirectURL.Hostname(), domain) {
			return true
		}
	}
	return false
}

// ValidateSignature ensures the request is valid and has been signed with
// the correspdoning client secret key
func ValidateSignature(f http.HandlerFunc, sharedSecret string) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		err := req.ParseForm()
		if err != nil {
			httputil.ErrorResponse(rw, req, err.Error(), http.StatusBadRequest)
			return
		}
		redirectURI := req.Form.Get("redirect_uri")
		sigVal := req.Form.Get("sig")
		timestamp := req.Form.Get("ts")
		if !validSignature(redirectURI, sigVal, timestamp, sharedSecret) {
			httputil.ErrorResponse(rw, req, "Invalid redirect parameter", http.StatusBadRequest)
			return
		}

		f(rw, req)
	}
}

// ValidateHost ensures that each request's host is valid
func ValidateHost(mux map[string]*http.Handler) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {

		return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			if _, ok := mux[req.Host]; !ok {
				httputil.ErrorResponse(rw, req, "Unknown host to route", http.StatusNotFound)
				return
			}
			next.ServeHTTP(rw, req)
		})
	}
}

// RequireHTTPS reroutes a HTTP request to HTTPS
// todo(bdd) : this is unreliable unless behind another reverser proxy
// todo(bdd) : header age seems extreme
func RequireHTTPS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Strict-Transport-Security", "max-age=31536000")
		// todo(bdd) : scheme and x-forwarded-proto cannot be trusted if not behind another load balancer
		if (req.URL.Scheme == "http" && req.Header.Get("X-Forwarded-Proto") == "http") || &req.TLS == nil {
			dest := &url.URL{
				Scheme:   "https",
				Host:     req.Host,
				Path:     req.URL.Path,
				RawQuery: req.URL.RawQuery,
			}
			http.Redirect(rw, req, dest.String(), http.StatusMovedPermanently)
			return
		}
		h.ServeHTTP(rw, req)
	})
}

func validSignature(redirectURI, sigVal, timestamp, secret string) bool {
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
