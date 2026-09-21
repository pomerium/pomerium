package file

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/secrets/provider"
	"github.com/pomerium/pomerium/pkg/secrets/provider/providertest"
	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

func fileRef(t *testing.T, path string) ref.Ref {
	t.Helper()
	return providertest.MustParseRef(t, "file://"+path)
}

// newFIFO creates a FIFO with no writer. open(2) for reading blocks until a
// writer appears, which stands in for a hung network or FUSE mount. Readers a
// test leaves parked are released at cleanup.
func newFIFO(t *testing.T) string {
	t.Helper()
	fifo := filepath.Join(t.TempDir(), "fifo")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	t.Cleanup(func() {
		// open(O_WRONLY|O_NONBLOCK) succeeds while a reader is present (waking
		// it) and fails with ENXIO once none is left.
		for range 200 {
			f, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0)
			if err != nil {
				return
			}
			_ = f.Close()
			time.Sleep(10 * time.Millisecond)
		}
	})
	return fifo
}

// requireGoroutinesBack waits for the goroutine count to return to baseline
// and dumps all stacks if it does not. It polls inline because
// assert.Eventually runs its condition on a helper goroutine, which would
// itself keep the count above baseline.
func requireGoroutinesBack(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(watchWait)
	for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
		time.Sleep(watchTick)
	}
	if now := runtime.NumGoroutine(); now > baseline {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("goroutines did not return to baseline %d (now %d):\n%s", baseline, now, buf[:n])
	}
}

func TestFetch(t *testing.T) {
	t.Parallel()

	t.Run("reads exact bytes, zero TTL", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "secret")
		require.NoError(t, os.WriteFile(path, []byte("s3cr3t-value"), 0o600))

		res, err := New().Fetch(context.Background(), fileRef(t, path))
		require.NoError(t, err)
		assert.Equal(t, "s3cr3t-value", string(res.Value))
		assert.Zero(t, res.TTL)
		assert.NotEmpty(t, res.Version)
	})

	t.Run("version tracks content", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "secret")
		r := fileRef(t, path)

		require.NoError(t, os.WriteFile(path, []byte("A"), 0o600))
		v1, err := New().Fetch(context.Background(), r)
		require.NoError(t, err)

		require.NoError(t, os.WriteFile(path, []byte("A"), 0o600))
		v1again, err := New().Fetch(context.Background(), r)
		require.NoError(t, err)
		assert.Equal(t, v1.Version, v1again.Version, "same content -> same version")

		require.NoError(t, os.WriteFile(path, []byte("B"), 0o600))
		v2, err := New().Fetch(context.Background(), r)
		require.NoError(t, err)
		assert.NotEqual(t, v1.Version, v2.Version, "changed content -> changed version")
	})

	t.Run("missing file is not-found", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "does-not-exist")
		_, err := New().Fetch(context.Background(), fileRef(t, path))
		require.Error(t, err)
		assert.True(t, provider.IsNotFound(err), "missing file must satisfy IsNotFound")
	})

	t.Run("unreadable file is transient", func(t *testing.T) {
		t.Parallel()
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("chmod-based permission test not meaningful here")
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "secret")
		require.NoError(t, os.WriteFile(path, []byte("x"), 0o000))

		_, err := New().Fetch(context.Background(), fileRef(t, path))
		require.Error(t, err)
		assert.False(t, provider.IsNotFound(err), "permission error is transient, not not-found")
	})

	t.Run("empty file is a valid empty value", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "secret")
		require.NoError(t, os.WriteFile(path, []byte(""), 0o600))

		res, err := New().Fetch(context.Background(), fileRef(t, path))
		require.NoError(t, err)
		assert.Empty(t, res.Value)
	})
}

func TestFetchSizeCap(t *testing.T) {
	t.Parallel()

	t.Run("exactly at the cap succeeds byte-exact", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "secret")
		want := bytes.Repeat([]byte("x"), MaxFileSize)
		require.NoError(t, os.WriteFile(path, want, 0o600))

		res, err := New().Fetch(context.Background(), fileRef(t, path))
		require.NoError(t, err)
		assert.Equal(t, want, res.Value)
	})

	t.Run("one byte over the cap is ErrTooLarge, never truncated", func(t *testing.T) {
		t.Parallel()
		path := filepath.Join(t.TempDir(), "secret")
		require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte("x"), MaxFileSize+1), 0o600))

		res, err := New().Fetch(context.Background(), fileRef(t, path))
		require.ErrorIs(t, err, provider.ErrTooLarge)
		assert.NotErrorIs(t, err, provider.ErrNotFound, "must not be negative-cached as missing")
		assert.Contains(t, err.Error(), path)
		assert.Empty(t, res.Value, "a truncated payload must not leak out alongside the error")
	})

	t.Run("cap applies before newline trimming", func(t *testing.T) {
		t.Parallel()
		// MaxFileSize payload bytes plus the one trailing newline D1 would strip:
		// the file on disk is over the cap even though the trimmed value is not.
		path := filepath.Join(t.TempDir(), "secret")
		data := append(bytes.Repeat([]byte("x"), MaxFileSize), '\n')
		require.NoError(t, os.WriteFile(path, data, 0o600))

		_, err := New().Fetch(context.Background(), fileRef(t, path))
		require.ErrorIs(t, err, provider.ErrTooLarge)
	})
}

func TestFetchTrailingNewline(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "single lf stripped", content: "tok\n", want: "tok"},
		{name: "crlf stripped", content: "tok\r\n", want: "tok"},
		{name: "only one lf stripped", content: "tok\n\n", want: "tok\n"},
		{name: "trailing space kept", content: "tok ", want: "tok "},
		{name: "embedded lf kept", content: "tok\nx", want: "tok\nx"},
		{name: "no trailing newline", content: "tok", want: "tok"},
		{name: "only newline", content: "\n", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "secret")
			require.NoError(t, os.WriteFile(path, []byte(tt.content), 0o600))

			res, err := New().Fetch(context.Background(), fileRef(t, path))
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(res.Value))
		})
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	p := New()

	t.Run("absolute path ok", func(t *testing.T) {
		t.Parallel()
		assert.NoError(t, p.Validate(fileRef(t, "/etc/pomerium/secret")))
	})

	t.Run("fragment accepted", func(t *testing.T) {
		t.Parallel()
		r, err := ref.Parse("file:///etc/x#data.token")
		require.NoError(t, err)
		assert.NoError(t, p.Validate(r))
	})

	t.Run("unknown query param rejected", func(t *testing.T) {
		t.Parallel()
		r, err := ref.Parse("file:///etc/x?foo=bar")
		require.NoError(t, err)
		assert.Error(t, p.Validate(r))
	})

	t.Run("query key without value rejected", func(t *testing.T) {
		t.Parallel()
		r, err := ref.Parse("file:///etc/x?foo")
		require.NoError(t, err)
		assert.Error(t, p.Validate(r))
	})

	t.Run("bare question mark accepted", func(t *testing.T) {
		t.Parallel()
		r, err := ref.Parse("file:///etc/x?")
		require.NoError(t, err)
		assert.NoError(t, p.Validate(r))
	})

	t.Run("error lists sorted keys", func(t *testing.T) {
		t.Parallel()
		r, err := ref.Parse("file:///etc/x?zeta=1&alpha=2")
		require.NoError(t, err)
		err = p.Validate(r)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "[alpha zeta]")
	})

	t.Run("root path ok", func(t *testing.T) {
		t.Parallel()
		assert.NoError(t, p.Validate(fileRef(t, "/")))
	})

	t.Run("percent-encoded path validates and fetch decodes it", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "my secret")
		require.NoError(t, os.WriteFile(path, []byte("v"), 0o600))
		r, err := ref.Parse("file://" + filepath.Join(dir, "my%20secret"))
		require.NoError(t, err)
		require.NoError(t, p.Validate(r))
		res, err := p.Fetch(context.Background(), r)
		require.NoError(t, err)
		assert.Equal(t, "v", string(res.Value))
	})
}

// The Provider doc promises that a Provider used only for validation never
// spawns goroutines.
func TestValidateSpawnsNoGoroutines(t *testing.T) {
	// Not parallel: goroutine counting.
	before := runtime.NumGoroutine()
	p := New()
	for range 50 {
		require.NoError(t, p.Validate(fileRef(t, "/etc/pomerium/secret")))
	}
	requireGoroutinesBack(t, before)
}

// The zero value must behave like New(): every method, Watch included.
func TestZeroValueProvider(t *testing.T) {
	t.Parallel()

	var p Provider
	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte("v1"), 0o600))
	r := fileRef(t, path)

	require.Equal(t, Scheme, p.Scheme())
	require.NoError(t, p.Validate(r))
	res, err := p.Fetch(context.Background(), r)
	require.NoError(t, err)
	require.Equal(t, "v1", string(res.Value))

	assert.NotPanics(t, func() {
		stop, err := p.Watch(context.Background(), r, func() {})
		if err == nil {
			stop()
		}
	}, "zero-value Provider: Fetch/Validate work but Watch panics")
}

func TestFetchRespectsContext(t *testing.T) {
	t.Parallel()

	t.Run("already cancelled", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		path := filepath.Join(dir, "secret")
		require.NoError(t, os.WriteFile(path, []byte("v1"), 0o600))

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := New().Fetch(ctx, fileRef(t, path))
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("already cancelled does not read", func(t *testing.T) {
		t.Parallel()

		// A cancelled fetch must not start the read at all: on a hung mount an
		// abandoned reader stays blocked in open(2) for the life of the process.
		// open(O_WRONLY|O_NONBLOCK) on a FIFO reports ENXIO only while nobody
		// holds it open for reading, which is the observation that pins this.
		fifo := newFIFO(t)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := New().Fetch(ctx, fileRef(t, fifo))
		require.ErrorIs(t, err, context.Canceled)

		time.Sleep(100 * time.Millisecond) // let any stray reader reach open(2)

		fd, err := syscall.Open(fifo, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = syscall.Close(fd)
		}
		assert.ErrorIs(t, err, syscall.ENXIO, "cancelled Fetch opened the file anyway")
	})

	t.Run("blocking read", func(t *testing.T) {
		t.Parallel()

		fifo := newFIFO(t)

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		done := make(chan error, 1)
		go func() {
			_, err := New().Fetch(ctx, fileRef(t, fifo))
			done <- err
		}()

		select {
		case err := <-done:
			assert.ErrorIs(t, err, context.DeadlineExceeded)
		case <-time.After(5 * time.Second):
			t.Error("Fetch ignored the context deadline on a blocking read")
		}
	})
}
