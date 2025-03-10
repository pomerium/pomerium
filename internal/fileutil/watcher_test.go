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
	t.Parallel()

	tmpdir := t.TempDir()

	err := os.WriteFile(filepath.Join(tmpdir, "test1.txt"), []byte{1}, 0o666)
	require.NoError(t, err)

	w := NewWatcher()
	defer w.Close()
	w.Watch([]string{filepath.Join(tmpdir, "test1.txt")})

	ch := w.Bind()
	t.Cleanup(func() { w.Unbind(ch) })

	err = os.WriteFile(filepath.Join(tmpdir, "test1.txt"), []byte{1, 2}, 0o666)
	require.NoError(t, err)

	expectChange(t, ch)
}

func TestWatcherSymlink(t *testing.T) {
	t.Parallel()

	tmpdir := t.TempDir()

	err := os.WriteFile(filepath.Join(tmpdir, "test1.txt"), []byte{1}, 0o666)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tmpdir, "test2.txt"), []byte{1, 2}, 0o666)
	require.NoError(t, err)

	assert.NoError(t, os.Symlink(filepath.Join(tmpdir, "test1.txt"), filepath.Join(tmpdir, "symlink1.txt")))

	w := NewWatcher()
	defer w.Close()
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
	t.Parallel()

	tmpdir := t.TempDir()

	err := os.WriteFile(filepath.Join(tmpdir, "test1.txt"), []byte{1}, 0o666)
	require.NoError(t, err)

	w := NewWatcher()
	defer w.Close()
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

func TestWatcher_FileModification(t *testing.T) {
	t.Parallel()

	tmpdir := t.TempDir()
	nm := filepath.Join(tmpdir, "test1.txt")
	now := time.Now()

	require.NoError(t, os.WriteFile(nm, []byte{1, 2, 3, 4}, 0o666))
	require.NoError(t, os.Chtimes(nm, now, now))

	w := NewWatcher()
	defer w.Close()
	w.Watch([]string{nm})

	ch := w.Bind()
	t.Cleanup(func() { w.Unbind(ch) })

	require.NoError(t, os.WriteFile(nm, []byte{5, 6, 7, 8}, 0o666))
	require.NoError(t, os.Chtimes(nm, now, now))

	expectChange(t, ch)
}

func TestWatcher_UnWatch(t *testing.T) {
	t.Parallel()

	tmpdir := t.TempDir()
	nm := filepath.Join(tmpdir, "test1.txt")
	now := time.Now()

	require.NoError(t, os.WriteFile(nm, []byte{1, 2, 3}, 0o666))
	require.NoError(t, os.Chtimes(nm, now, now))

	w := NewWatcher()
	defer w.Close()

	ch := w.Bind()
	t.Cleanup(func() { w.Unbind(ch) })

	w.Watch([]string{nm})
	require.NoError(t, os.WriteFile(nm, []byte{4, 5, 6}, 0o666))
	require.NoError(t, os.Chtimes(nm, now, now))
	expectChange(t, ch)

	w.Watch(nil)
	require.NoError(t, os.WriteFile(nm, []byte{7, 8, 9}, 0o666))
	require.NoError(t, os.Chtimes(nm, now, now))
	expectNoChange(t, ch)
}

func expectChange(t *testing.T, ch chan context.Context) {
	t.Helper()

	cnt := 0
	select {
	case <-ch:
		cnt++
	case <-time.After(2 * pollingInterval):
	}
	assert.Greater(t, cnt, 0, "should signal a change")
}

func expectNoChange(t *testing.T, ch chan context.Context) {
	t.Helper()

	cnt := 0
	select {
	case <-ch:
		cnt++
	case <-time.After(2 * pollingInterval):
	}
	assert.Equal(t, 0, cnt, "should not signal a change")
}
