package httputil

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-jose/go-jose/v3"

	"github.com/pomerium/csrf"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// HealthCheck is a simple healthcheck handler that responds to GET and HEAD
// http requests.
func HealthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		fmt.Fprintln(w, http.StatusText(http.StatusOK))
	}
}

// Redirect wraps the std libs's redirect method indicating that pomerium is
// the origin of the response.
func Redirect(w http.ResponseWriter, r *http.Request, url string, code int) {
	w.Header().Set(HeaderPomeriumResponse, "true")
	http.Redirect(w, r, url, code)
}

// RenderJSON replies to the request with the specified struct as JSON and HTTP code.
// It does not otherwise end the request; the caller should ensure no further
// writes are done to w.
// The error message should be application/json.
func RenderJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	b := new(bytes.Buffer)
	if err := json.NewEncoder(b).Encode(v); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(b, `{"error":"%s"}`, err)
	} else {
		w.WriteHeader(code)
	}
	fmt.Fprint(w, b)
}

// The HandlerFunc type is an adapter to allow the use of
// ordinary functions as HTTP handlers. If f is a function
// with the appropriate signature, HandlerFunc(f) is a
// Handler that calls f.
//
// adapted from std library to support error wrapping
type HandlerFunc func(http.ResponseWriter, *http.Request) error

// ServeHTTP calls f(w, r) error.
func (f HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := f(w, r); err != nil {
		var e *HTTPError
		if !errors.As(err, &e) {
			e = &HTTPError{Status: http.StatusInternalServerError, Err: err}
		}
		e.ErrorResponse(r.Context(), w, r)
	}
}

// JWKSHandler returns the /.well-known/pomerium/jwks.json handler.
func JWKSHandler(rawSigningKey string) http.Handler {
	return HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		var jwks jose.JSONWebKeySet
		if rawSigningKey != "" {
			decodedCert, err := base64.StdEncoding.DecodeString(rawSigningKey)
			if err != nil {
				return NewError(http.StatusInternalServerError, errors.New("bad signing key"))
			}
			jwk, err := cryptutil.PublicJWKFromBytes(decodedCert)
			if err != nil {
				return NewError(http.StatusInternalServerError, errors.New("bad signing key"))
			}
			jwks.Keys = append(jwks.Keys, *jwk)
		}
		RenderJSON(w, http.StatusOK, jwks)
		return nil
	})
}

// WellKnownPomeriumHandler returns the /.well-known/pomerium handler.
func WellKnownPomeriumHandler(authenticateURL *url.URL) http.Handler {
	return HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		wellKnownURLs := struct {
			OAuth2Callback        string `json:"authentication_callback_endpoint"` // RFC6749
			JSONWebKeySetURL      string `json:"jwks_uri"`                         // RFC7517
			FrontchannelLogoutURI string `json:"frontchannel_logout_uri"`          // https://openid.net/specs/openid-connect-frontchannel-1_0.html
		}{
			authenticateURL.ResolveReference(&url.URL{Path: "/oauth2/callback"}).String(),
			authenticateURL.ResolveReference(&url.URL{Path: "/.well-known/pomerium/jwks.json"}).String(),
			authenticateURL.ResolveReference(&url.URL{Path: "/.pomerium/sign_out"}).String(),
		}
		w.Header().Set("X-CSRF-Token", csrf.Token(r))
		RenderJSON(w, http.StatusOK, wellKnownURLs)
		return nil
	})
}
