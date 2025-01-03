//go:build !darwin

package testenv

import "testing"

func tempDir(t testing.TB) string {
	return t.TempDir()
}
