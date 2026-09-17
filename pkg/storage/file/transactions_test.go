package file_test

import (
	"testing"

	"go.opentelemetry.io/otel/trace/noop"

	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/storage/file"
	"github.com/pomerium/pomerium/pkg/storage/storagetest"
)

func newTransactionBackend(t *testing.T) storage.Backend {
	t.Helper()
	backend := file.New(noop.NewTracerProvider(), "memory://")
	t.Cleanup(func() { _ = backend.Close() })
	return backend
}

func TestTransactions(t *testing.T) {
	storagetest.TestTransaction(t, newTransactionBackend)
}
