// Package requestid has functions for working with x-request-id in http/gRPC requests.
package requestid

import (
	"context"

	"github.com/google/uuid"

	"github.com/akamensky/base58"
)

const headerName = "x-request-id"

type contextKey struct{}

// WithValue returns a new context from the parent context with a request id value set.
func WithValue(parent context.Context, requestID string) context.Context {
	return context.WithValue(parent, contextKey{}, requestID)
}

// FromContext gets the request id from a context.
func FromContext(ctx context.Context) string {
	if id, ok := ctx.Value(contextKey{}).(string); ok {
		return id
	}
	return ""
}

// New creates a new request id.
func New() string {
	id := uuid.New()
	return base58.Encode(id[:])
}
