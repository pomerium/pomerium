package file_test

import (
	"testing"

	"github.com/pomerium/pomerium/pkg/storage/file"
	"github.com/pomerium/pomerium/pkg/storage/storagetest"
)

func TestRegistry(t *testing.T) {
	t.Parallel()

	backend := file.New("memory://")
	t.Cleanup(func() { _ = backend.Close() })

	storagetest.TestRegistry(t, backend.RegistryServer())
}
