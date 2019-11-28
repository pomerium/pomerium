package httputil // import "github.com/pomerium/pomerium/internal/httputil"

import (
	"errors"
	"fmt"
	"net/http"
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

// The HandlerFunc type is an adapter to allow the use of
// ordinary functions as HTTP handlers. If f is a function
// with the appropriate signature, HandlerFunc(f) is a
// Handler that calls f.
//
// adapted from std library to suppport error wrapping
type HandlerFunc func(http.ResponseWriter, *http.Request) error

// ServeHTTP calls f(w, r) error.
func (f HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := f(w, r); err != nil {
		var e *HTTPError
		if !errors.As(err, &e) {
			e = &HTTPError{http.StatusInternalServerError, err}
		}
		e.ErrorResponse(w, r)
	}
}
