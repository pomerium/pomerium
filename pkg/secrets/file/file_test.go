package file

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/secrets/provider"
	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

func fileRef(t *testing.T, path string) ref.Ref {
	t.Helper()
	r, err := ref.Parse("file://" + path)
	require.NoError(t, err)
	return r
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
}
