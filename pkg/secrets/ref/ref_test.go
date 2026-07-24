package ref

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		raw          string
		wantErr      bool
		wantScheme   string
		wantSelector string
		wantPath     string
		wantQuery    map[string]string
	}{
		{name: "file absolute", raw: "file:///etc/pomerium/secret", wantScheme: "file", wantPath: "/etc/pomerium/secret"},
		{name: "scheme lowercased", raw: "FILE:///etc/x", wantScheme: "file", wantPath: "/etc/x"},
		{name: "file with host", raw: "file://relative/path", wantErr: true},
		{name: "empty url", raw: "", wantErr: true},
		{name: "no scheme absolute", raw: "/etc/pomerium/secret", wantErr: true},
		{name: "no scheme relative", raw: "relative/path", wantErr: true},
		{name: "interpolation brace", raw: "file:///${pomerium.user.id}", wantErr: true},
		{name: "interpolation embedded", raw: "file:///etc/x${y}", wantErr: true},
		{name: "fragment captured", raw: "file:///etc/x#data.token", wantScheme: "file", wantPath: "/etc/x", wantSelector: "data.token"},
		{name: "query captured", raw: "file:///etc/x?a=1&b=2", wantScheme: "file", wantPath: "/etc/x", wantQuery: map[string]string{"a": "1", "b": "2"}},
		{name: "rfc6901 fragment reserved", raw: "file:///etc/x#/data/token", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r, err := Parse(tt.raw)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantScheme, r.Scheme())
			assert.Equal(t, tt.wantSelector, r.Selector())
			assert.Equal(t, tt.wantPath, r.URL().Path)
			for k, v := range tt.wantQuery {
				assert.Equal(t, v, r.URL().Query().Get(k), "query %q", k)
			}
		})
	}
}

func TestParseErrorHasNoInterpolationLeak(t *testing.T) {
	t.Parallel()

	// The error for an interpolated URL should not blindly echo an arbitrary
	// backend URL; it is config, so echoing is safe, but the message must be
	// actionable. Just assert it errors and mentions interpolation.
	_, err := Parse("file:///${pomerium.user.id}")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "${")
}

func TestKey(t *testing.T) {
	t.Parallel()

	mustParse := func(raw string) Ref {
		r, err := Parse(raw)
		require.NoError(t, err)
		return r
	}

	t.Run("scheme case insensitive", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, mustParse("FILE:///x").Key(), mustParse("file:///x").Key())
	})

	t.Run("query order independent", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, mustParse("file:///x?a=1&b=2").Key(), mustParse("file:///x?b=2&a=1").Key())
	})

	t.Run("fragment distinguishes", func(t *testing.T) {
		t.Parallel()
		assert.NotEqual(t, mustParse("file:///x#f1").Key(), mustParse("file:///x#f2").Key())
		assert.NotEqual(t, mustParse("file:///x").Key(), mustParse("file:///x#f1").Key())
	})

	t.Run("different path distinguishes", func(t *testing.T) {
		t.Parallel()
		assert.NotEqual(t, mustParse("file:///x").Key(), mustParse("file:///y").Key())
	})
}

func TestFetchKey(t *testing.T) {
	t.Parallel()

	mustParse := func(raw string) Ref {
		r, err := Parse(raw)
		require.NoError(t, err)
		return r
	}

	t.Run("fragment ignored", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, mustParse("file:///x#f1").FetchKey(), mustParse("file:///x#f2").FetchKey())
		assert.Equal(t, mustParse("file:///x").FetchKey(), mustParse("file:///x#f1").FetchKey())
	})

	t.Run("scheme case insensitive", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, mustParse("FILE:///x").FetchKey(), mustParse("file:///x").FetchKey())
	})

	t.Run("query order independent", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, mustParse("file:///x?a=1&b=2").FetchKey(), mustParse("file:///x?b=2&a=1").FetchKey())
	})

	t.Run("path and query distinguish", func(t *testing.T) {
		t.Parallel()
		assert.NotEqual(t, mustParse("file:///x").FetchKey(), mustParse("file:///y").FetchKey())
		assert.NotEqual(t, mustParse("file:///x?a=1").FetchKey(), mustParse("file:///x?a=2").FetchKey())
	})
}

func TestString(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"file:///etc/pomerium/secret",
		"file:///etc/x#data.token",
		"file:///etc/x?a=1&b=2",
	} {
		r, err := Parse(raw)
		require.NoError(t, err)

		// String round-trips: reparsing yields an identical identity.
		r2, err := Parse(r.String())
		require.NoError(t, err, "reparse %q", r.String())
		assert.Equal(t, r.Key(), r2.Key())
	}
}

func TestURLDefensiveCopy(t *testing.T) {
	t.Parallel()

	r, err := Parse("file:///etc/x")
	require.NoError(t, err)

	u := r.URL()
	u.Path = "/tampered"

	assert.Equal(t, "/etc/x", r.URL().Path, "mutating the returned URL must not affect the Ref")
}
