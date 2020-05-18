// Package requestid has functions for working with x-request-id in http/gRPC requests.
package requestid

import (
	"context"

	shortuuid "github.com/lithammer/shortuuid/v3"
)

const headerName = "x-request-id"

var contextKey struct{}

// WithValue returns a new context from the parent context with a request id value set.
func WithValue(parent context.Context, requestID string) context.Context {
	return context.WithValue(parent, contextKey, requestID)
}

// FromContext gets the request id from a context.
func FromContext(ctx context.Context) string {
	if id, ok := ctx.Value(contextKey).(string); ok {
		return id
	}
	return ""
}

// New creates a new request id.
func New() string {
	return shortuuid.New()
}
