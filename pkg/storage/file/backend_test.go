package file_test

import (
	"testing"

	"github.com/pomerium/pomerium/pkg/storage/file"
	"github.com/pomerium/pomerium/pkg/storage/storagetest"
)

func TestBackend(t *testing.T) {
	backend := file.New("memory://")
	storagetest.TestBackend(t, backend)
}
