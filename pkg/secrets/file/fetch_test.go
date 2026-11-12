package file

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/secrets/provider"
	"github.com/pomerium/pomerium/pkg/secrets/provider/providertest"
	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

// A secret that cannot come into existence without a config or mount change
// must classify as not-found so the resolver negative-caches it instead of
// retrying with backoff forever. ENOENT already does; ENOTDIR (a path component
// that is a regular file) and EISDIR (the ref names a directory) are the same
// kind of permanent misconfiguration.
func TestFetchErrorClassification(t *testing.T) {
	t.Parallel()

	t.Run("path through a regular file is not-found", func(t *testing.T) {
		t.Parallel()
		regular := filepath.Join(t.TempDir(), "regular")
		require.NoError(t, os.WriteFile(regular, []byte("x"), 0o600))

		for _, path := range []string{
			filepath.Join(regular, "child"), // .../regular/child
			regular + "/",                   // trailing slash on a regular file
		} {
			_, err := New().Fetch(context.Background(), fileRef(t, path))
			require.Error(t, err, path)
			assert.True(t, provider.IsNotFound(err), "%s: ENOTDIR classified as transient: %v", path, err)
		}
	})

	t.Run("directory is not-found", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		_, err := New().Fetch(context.Background(), fileRef(t, dir))
		require.Error(t, err)
		assert.True(t, provider.IsNotFound(err), "EISDIR classified as transient: %v", err)
	})

	t.Run("dangling symlink is not-found", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		link := filepath.Join(dir, "link")
		require.NoError(t, os.Symlink(filepath.Join(dir, "gone"), link))
		_, err := New().Fetch(context.Background(), fileRef(t, link))
		require.Error(t, err)
		assert.True(t, provider.IsNotFound(err))
	})
}

func TestFetchFollowsSymlink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("tok\n"), 0o600))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(target, link))

	a, err := New().Fetch(context.Background(), fileRef(t, target))
	require.NoError(t, err)
	b, err := New().Fetch(context.Background(), fileRef(t, link))
	require.NoError(t, err)
	assert.Equal(t, "tok", string(b.Value))
	assert.Equal(t, a.Value, b.Value)
	assert.Equal(t, a.Version, b.Version, "symlink and target share a version")
}

func TestFetchVersionIgnoresTrailingNewline(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	require.NoError(t, os.WriteFile(a, []byte("tok"), 0o600))
	require.NoError(t, os.WriteFile(b, []byte("tok\n"), 0o600))

	ra, err := New().Fetch(context.Background(), fileRef(t, a))
	require.NoError(t, err)
	rb, err := New().Fetch(context.Background(), fileRef(t, b))
	require.NoError(t, err)
	assert.Equal(t, ra.Version, rb.Version, "version hashes the trimmed value")
}

// An endless device must not be read at all. Reading it would only stop at
// the size cap, so the cap is a backstop; the file-type check is what rejects
// it, and permanently, since no device ever becomes a valid secret.
func TestFetchRejectsNonRegularFiles(t *testing.T) {
	t.Parallel()

	t.Run("character device", func(t *testing.T) {
		t.Parallel()
		if _, err := os.Stat("/dev/zero"); err != nil {
			t.Skip("/dev/zero unavailable")
		}
		_, err := New().Fetch(context.Background(), fileRef(t, "/dev/zero"))
		require.Error(t, err)
		assert.True(t, provider.IsNotFound(err), "endless device classified as transient: %v", err)
	})

	t.Run("fifo fails fast instead of blocking in open", func(t *testing.T) {
		t.Parallel()
		fifo := newFIFO(t)

		done := make(chan error, 1)
		go func() {
			_, err := New().Fetch(context.Background(), fileRef(t, fifo))
			done <- err
		}()

		select {
		case err := <-done:
			require.Error(t, err)
			assert.True(t, provider.IsNotFound(err), "%v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("Fetch blocked opening a FIFO; the open is not non-blocking")
		}
	})
}

func TestFetchConcurrent(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte("v"), 0o600))
	p := New()
	r := fileRef(t, path)

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			res, err := p.Fetch(context.Background(), r)
			assert.NoError(t, err)
			assert.Equal(t, "v", string(res.Value))
		})
	}
	wg.Wait()
}

// Nothing ties Fetch to Validate: there is no validated-ref type and Fetch
// re-checks nothing, so a ref that config validation rejects (or a ref of a
// different scheme entirely) is served from disk, and the zero ref.Ref panics
// instead of erroring.
func TestFetchRejectsUnvalidatedRef(t *testing.T) {
	t.Parallel()

	p := New()
	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte("top-secret"), 0o600))

	t.Run("unsupported query params", func(t *testing.T) {
		t.Parallel()
		r := providertest.MustParseRef(t, "file://"+path+"?version=2")
		require.Error(t, p.Validate(r))
		res, err := p.Fetch(context.Background(), r)
		assert.Error(t, err, "Fetch served a ref Validate rejects: %q", res.Value)
	})

	t.Run("foreign scheme", func(t *testing.T) {
		t.Parallel()
		r := providertest.MustParseRef(t, "vault://"+path)
		assert.Error(t, p.Validate(r), "file provider validated a vault:// ref")
		res, err := p.Fetch(context.Background(), r)
		assert.Error(t, err, "file provider read the local file for a vault:// ref: %q", res.Value)
	})

	t.Run("zero ref", func(t *testing.T) {
		t.Parallel()
		assert.NotPanics(t, func() { _ = p.Validate(ref.Ref{}) }, "Validate(zero ref)")
		assert.NotPanics(t, func() { _, _ = p.Fetch(context.Background(), ref.Ref{}) }, "Fetch(zero ref)")
	})
}

// A read abandoned on a path that never returns must not answer for later
// fetches of that path: the secret has to come back as soon as the file does.
func TestFetchRecoversAfterBlockedPathIsReplaced(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	blocked := filepath.Join(dir, "blocked")
	require.NoError(t, syscall.Mkfifo(path, 0o600))

	p := New()
	r := fileRef(t, path)

	// A FIFO is refused outright now, but the recovery property must hold for
	// any first fetch that fails without leaving the path claimed.
	_, err := p.Fetch(context.Background(), r)
	require.Error(t, err)

	require.NoError(t, os.Rename(path, blocked))
	require.NoError(t, os.WriteFile(path, []byte("recovered"), 0o600))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := p.Fetch(ctx, r)
	require.NoError(t, err)
	assert.Equal(t, "recovered", string(got.Value))
}

// The same recovery property for a fetch abandoned mid-read: the reader stays
// parked on the old inode, and the next fetch must still see the new file.
func TestFetchRecoversAfterCancelledReadIsReplaced(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	slow := filepath.Join(dir, "slow")
	require.NoError(t, syscall.Mkfifo(slow, 0o600))
	require.NoError(t, os.Symlink(slow, path))

	p := New()
	r := fileRef(t, path)

	ctx1, cancel1 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	_, err := p.Fetch(ctx1, r)
	cancel1()
	require.Error(t, err)

	require.NoError(t, os.Remove(path))
	require.NoError(t, os.WriteFile(path, []byte("recovered"), 0o600))

	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	got, err := p.Fetch(ctx2, r)
	require.NoError(t, err)
	assert.Equal(t, "recovered", string(got.Value))
}
