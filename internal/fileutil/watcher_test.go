package fileutil

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWatcher(t *testing.T) {
	tmpdir := t.TempDir()

	err := os.WriteFile(filepath.Join(tmpdir, "test1.txt"), []byte{1}, 0o666)
	require.NoError(t, err)

	w := NewWatcher()
	w.Watch([]string{filepath.Join(tmpdir, "test1.txt")})

	ch := w.Bind()
	t.Cleanup(func() { w.Unbind(ch) })

	err = os.WriteFile(filepath.Join(tmpdir, "test1.txt"), []byte{1, 2}, 0o666)
	require.NoError(t, err)

	expectChange(t, ch)
}

func TestWatcherSymlink(t *testing.T) {
	tmpdir := t.TempDir()

	err := os.WriteFile(filepath.Join(tmpdir, "test1.txt"), []byte{1}, 0o666)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tmpdir, "test2.txt"), []byte{1, 2}, 0o666)
	require.NoError(t, err)

	assert.NoError(t, os.Symlink(filepath.Join(tmpdir, "test1.txt"), filepath.Join(tmpdir, "symlink1.txt")))

	w := NewWatcher()
	w.Watch([]string{filepath.Join(tmpdir, "symlink1.txt")})

	ch := w.Bind()
	t.Cleanup(func() { w.Unbind(ch) })

	assert.NoError(t, os.WriteFile(filepath.Join(tmpdir, "test1.txt"), []byte{1, 2, 3}, 0o666))

	expectChange(t, ch)

	assert.NoError(t, os.Symlink(filepath.Join(tmpdir, "test2.txt"), filepath.Join(tmpdir, "symlink2.txt")))
	assert.NoError(t, os.Rename(filepath.Join(tmpdir, "symlink2.txt"), filepath.Join(tmpdir, "symlink1.txt")))

	expectChange(t, ch)
}

func TestWatcher_FileRemoval(t *testing.T) {
	tmpdir := t.TempDir()

	err := os.WriteFile(filepath.Join(tmpdir, "test1.txt"), []byte{1}, 0o666)
	require.NoError(t, err)

	w := NewWatcher()
	w.Watch([]string{filepath.Join(tmpdir, "test1.txt")})

	ch := w.Bind()
	t.Cleanup(func() { w.Unbind(ch) })

	err = os.Remove(filepath.Join(tmpdir, "test1.txt"))
	require.NoError(t, err)

	expectChange(t, ch)

	err = os.WriteFile(filepath.Join(tmpdir, "test1.txt"), []byte{1, 2}, 0o666)
	require.NoError(t, err)

	expectChange(t, ch)
}

func expectChange(t *testing.T, ch chan context.Context) {
	t.Helper()

	cnt := 0
	select {
	case <-ch:
		cnt++
	case <-time.After(10 * time.Second):
	}
	if cnt == 0 {
		t.Error("expected change signal")
	}
}
