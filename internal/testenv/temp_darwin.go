//go:build darwin

package testenv

import (
	"os"
	"testing"
)

// macos temp directory names are too long
// https://github.com/golang/go/issues/62614
func tempDir(t testing.TB) string {
	dir, err := os.MkdirTemp("", "test") //nolint:usetesting
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.RemoveAll(dir)
	})
	return dir
}
