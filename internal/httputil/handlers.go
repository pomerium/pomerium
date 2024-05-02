package httputil

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

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
func RenderJSON(w http.ResponseWriter, code int, v any) {
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
