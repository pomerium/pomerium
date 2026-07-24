// Package provider defines the secret backend abstraction: the Provider
// interface every scheme implements, the error taxonomy the resolver keys its
// caching decisions off of, and a scheme Registry shared by config validation
// and the authorize runtime.
package provider

import (
	"context"
	"time"

	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

// Result is the outcome of a single successful fetch.
type Result struct {
	// Value is the raw backend payload, before any selector is applied.
	Value []byte
	// TTL is the provider-supplied lifetime; 0 means the provider has no TTL
	// notion and the resolver falls back to flat polling.
	TTL time.Duration
	// Version is an opaque change-detection token used only for logging and
	// metrics. It never contains secret material.
	Version string
}

// Provider fetches secret payloads for a single URL scheme.
type Provider interface {
	// Scheme returns the lowercased URL scheme this provider handles.
	Scheme() string
	// Validate strictly checks a ref for this scheme: unknown query params,
	// bad paths, etc. all fail. It never performs I/O.
	Validate(r ref.Ref) error
	// Fetch retrieves the current raw payload for r.
	Fetch(ctx context.Context, r ref.Ref) (Result, error)
}

// Watcher is an optional Provider capability: pushing change hints to the
// resolver so a rotated value becomes visible without waiting for the next
// scheduled refresh.
type Watcher interface {
	// Watch calls notify (coalescing allowed) whenever the referenced secret
	// may have changed, until ctx is done or the returned stop func is called.
	Watch(ctx context.Context, r ref.Ref, notify func()) (stop func(), err error)
}
