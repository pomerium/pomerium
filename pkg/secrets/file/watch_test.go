package file

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	watchWait = 3 * time.Second
	watchTick = 50 * time.Millisecond
)

func TestWatchDetectsRewrite(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(path, []byte("v1"), 0o600))

	var count atomic.Int64
	stop, err := New().Watch(context.Background(), fileRef(t, path), func() { count.Add(1) })
	require.NoError(t, err)
	defer stop()

	require.NoError(t, os.WriteFile(path, []byte("v2"), 0o600))
	assert.Eventually(t, func() bool { return count.Load() > 0 }, watchWait, watchTick)
}

func TestWatchDetectsAtomicSymlinkSwap(t *testing.T) {
	t.Parallel()

	// Emulate a Kubernetes projected-volume layout:
	//   <dir>/token   -> ..data/token   (symlink)
	//   <dir>/..data  -> ..v1           (symlink)
	// Rotation atomically renames a new ..data symlink into place.
	dir := t.TempDir()

	v1 := filepath.Join(dir, "..v1")
	require.NoError(t, os.Mkdir(v1, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(v1, "token"), []byte("v1"), 0o600))
	require.NoError(t, os.Symlink(v1, filepath.Join(dir, "..data")))

	tokenPath := filepath.Join(dir, "token")
	require.NoError(t, os.Symlink(filepath.Join("..data", "token"), tokenPath))

	var count atomic.Int64
	stop, err := New().Watch(context.Background(), fileRef(t, tokenPath), func() { count.Add(1) })
	require.NoError(t, err)
	defer stop()

	// Rotate: new versioned dir + atomic ..data symlink swap.
	v2 := filepath.Join(dir, "..v2")
	require.NoError(t, os.Mkdir(v2, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(v2, "token"), []byte("v2"), 0o600))
	tmp := filepath.Join(dir, "..data_tmp")
	require.NoError(t, os.Symlink(v2, tmp))
	require.NoError(t, os.Rename(tmp, filepath.Join(dir, "..data")))

	assert.Eventually(t, func() bool { return count.Load() > 0 }, watchWait, watchTick)
}

func TestWatchDetectsCreateAfterMissing(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "not-yet")

	var count atomic.Int64
	stop, err := New().Watch(context.Background(), fileRef(t, path), func() { count.Add(1) })
	require.NoError(t, err)
	defer stop()

	require.NoError(t, os.WriteFile(path, []byte("appeared"), 0o600))
	assert.Eventually(t, func() bool { return count.Load() > 0 }, watchWait, watchTick)
}

func TestWatchStop(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(path, []byte("v1"), 0o600))

	var count atomic.Int64
	stop, err := New().Watch(context.Background(), fileRef(t, path), func() { count.Add(1) })
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(path, []byte("v2"), 0o600))
	assert.Eventually(t, func() bool { return count.Load() > 0 }, watchWait, watchTick)

	stop()
	before := count.Load()

	require.NoError(t, os.WriteFile(path, []byte("v3"), 0o600))
	time.Sleep(time.Second) // real time: give the (stopped) watcher a chance to (not) fire
	assert.Equal(t, before, count.Load(), "no notifications after stop")
}
