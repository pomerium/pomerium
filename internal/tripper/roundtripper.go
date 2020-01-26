// Package tripper provides utility functions for working with the
// http.RoundTripper interface.
package tripper // import "github.com/pomerium/pomerium/internal/tripper"

import (
	"net/http"
)

// RoundTripperFunc wraps a function in a RoundTripper interface similar to HandlerFunc
type RoundTripperFunc func(*http.Request) (*http.Response, error)

// RoundTrip calls the underlying tripper function in the RoundTripperFunc
func (f RoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
