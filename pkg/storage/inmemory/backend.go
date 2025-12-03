// Package inmemory contains an in-memory implementation of the databroker backend.
package inmemory

import (
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/pkg/storage/file"
)

// New creates a new in-memory backend storage.
func New(tracerProvider oteltrace.TracerProvider) *file.Backend {
	return file.New(tracerProvider, "memory://")
}
