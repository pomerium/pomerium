package fileutil

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestWatcher(t *testing.T) {
	tmpdir := filepath.Join(os.TempDir(), uuid.New().String())
	err := os.MkdirAll(tmpdir, 0o755)
	if !assert.NoError(t, err) {
		return
	}

	err = os.WriteFile(filepath.Join(tmpdir, "test1.txt"), []byte{1, 2, 3, 4}, 0o666)
	if !assert.NoError(t, err) {
		return
	}

	w := NewWatcher()
	defer w.Clear()
	w.Add(filepath.Join(tmpdir, "test1.txt"))

	ch := w.Bind()
	defer w.Unbind(ch)

	err = os.WriteFile(filepath.Join(tmpdir, "test1.txt"), []byte{5, 6, 7, 8}, 0o666)
	if !assert.NoError(t, err) {
		return
	}

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Error("expected change signal when file is modified")
	}
}

func TestWatcherSymlink(t *testing.T) {
	t.Parallel()

	tmpdir := filepath.Join(os.TempDir(), uuid.New().String())
	err := os.MkdirAll(tmpdir, 0o755)
	if !assert.NoError(t, err) {
		return
	}
	t.Cleanup(func() { os.RemoveAll(tmpdir) })

	err = os.WriteFile(filepath.Join(tmpdir, "test1.txt"), []byte{1, 2, 3, 4}, 0o666)
	if !assert.NoError(t, err) {
		return
	}

	err = os.WriteFile(filepath.Join(tmpdir, "test2.txt"), []byte{5, 6, 7, 8}, 0o666)
	if !assert.NoError(t, err) {
		return
	}

	assert.NoError(t, os.Symlink(filepath.Join(tmpdir, "test1.txt"), filepath.Join(tmpdir, "symlink1.txt")))

	w := NewWatcher()
	defer w.Clear()
	w.Add(filepath.Join(tmpdir, "symlink1.txt"))

	ch := w.Bind()
	t.Cleanup(func() { w.Unbind(ch) })

	assert.NoError(t, os.WriteFile(filepath.Join(tmpdir, "test1.txt"), []byte{9, 10, 11}, 0o666))

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Error("expected change signal when underlying file is modified")
	}

	assert.NoError(t, os.Symlink(filepath.Join(tmpdir, "test2.txt"), filepath.Join(tmpdir, "symlink2.txt")))
	assert.NoError(t, os.Rename(filepath.Join(tmpdir, "symlink2.txt"), filepath.Join(tmpdir, "symlink1.txt")))

	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Error("expected change signal when symlink is changed")
	}
}
