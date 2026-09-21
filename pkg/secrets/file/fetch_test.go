package file

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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

func TestFetchUnboundedDeviceIsTooLarge(t *testing.T) {
	t.Parallel()

	if _, err := os.Stat("/dev/zero"); err != nil {
		t.Skip("/dev/zero unavailable")
	}
	_, err := New().Fetch(context.Background(), fileRef(t, "/dev/zero"))
	require.ErrorIs(t, err, provider.ErrTooLarge)
}

func TestFetchConcurrent(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte("v"), 0o600))
	p := New()
	r := fileRef(t, path)

	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := p.Fetch(context.Background(), r)
			assert.NoError(t, err)
			assert.Equal(t, "v", string(res.Value))
		}()
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

func countParkedReaders() int {
	buf := make([]byte, 4<<20)
	n := runtime.Stack(buf, true)
	return strings.Count(string(buf[:n]), "file.readCapped(")
}

// Every cancelled Fetch on a blocking path abandons a fresh reader goroutine
// and nothing dedupes reads of the same path, so a retry loop against a hung
// mount grows one parked goroutine (and fd) per attempt for the life of the
// process. Expected: at most one in-flight reader per path.
func TestFetchDedupesAbandonedReaders(t *testing.T) {
	// Not parallel: the goroutine census must not see other tests' FIFO readers.
	fifo := newFIFO(t)
	r := fileRef(t, fifo)
	p := New()

	before := countParkedReaders()

	const attempts = 5
	for range attempts {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := p.Fetch(ctx, r)
		cancel()
		require.ErrorIs(t, err, context.DeadlineExceeded)
	}
	leaked := countParkedReaders() - before

	assert.LessOrEqual(t, leaked, 1,
		"%d cancelled fetches of one path left %d readers parked in open(2)", attempts, leaked)
}
