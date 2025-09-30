package file_test

import (
	"testing"

	"go.opentelemetry.io/otel/trace/noop"

	"github.com/pomerium/pomerium/pkg/storage/file"
	"github.com/pomerium/pomerium/pkg/storage/storagetest"
)

func TestRegistry(t *testing.T) {
	t.Parallel()

	backend := file.New(noop.NewTracerProvider(), "memory://")
	t.Cleanup(func() { _ = backend.Close() })

	storagetest.TestRegistry(t, backend.RegistryServer())
}
