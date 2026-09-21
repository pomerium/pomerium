package provider_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/secrets/provider"
	"github.com/pomerium/pomerium/pkg/secrets/provider/providertest"
)

func TestRegistry(t *testing.T) {
	t.Parallel()

	t.Run("register enables validation", func(t *testing.T) {
		t.Parallel()
		reg := provider.NewRegistry()
		require.NoError(t, reg.Register(providertest.New("file")))

		assert.NoError(t, reg.Validate(providertest.MustParseRef(t, "file:///etc/x")))

		p, ok := reg.Get("file")
		assert.True(t, ok)
		assert.Equal(t, "file", p.Scheme())
		assert.Equal(t, []string{"file"}, reg.Schemes())
	})

	t.Run("uppercase ref resolves to lowercase scheme", func(t *testing.T) {
		t.Parallel()
		reg := provider.NewRegistry()
		require.NoError(t, reg.Register(providertest.New("file")))
		assert.NoError(t, reg.Validate(providertest.MustParseRef(t, "FILE:///etc/x")))
	})

	t.Run("unknown scheme names scheme and known set", func(t *testing.T) {
		t.Parallel()
		reg := provider.NewRegistry()
		require.NoError(t, reg.Register(providertest.New("file")))

		err := reg.Validate(providertest.MustParseRef(t, "vault:///secret/data/x"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "vault")
		assert.Contains(t, err.Error(), "file")
	})

	t.Run("empty registry names the scheme", func(t *testing.T) {
		t.Parallel()
		reg := provider.NewRegistry()
		err := reg.Validate(providertest.MustParseRef(t, "file:///etc/x"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), `"file"`)
		_, ok := reg.Get("file")
		assert.False(t, ok)
		assert.Empty(t, reg.Schemes())
	})

	t.Run("duplicate registration is an error and keeps the original", func(t *testing.T) {
		t.Parallel()
		reg := provider.NewRegistry()
		require.NoError(t, reg.Register(providertest.New("file")))
		second := providertest.New("file")
		second.SetValidateErr(assert.AnError)
		err := reg.Register(second)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "file")
		assert.NoError(t, reg.Validate(providertest.MustParseRef(t, "file:///x")), "second registration must not replace the first")
	})

	t.Run("validate delegates to provider", func(t *testing.T) {
		t.Parallel()
		reg := provider.NewRegistry()
		sentinel := errors.New("bad param")
		f := providertest.New("file")
		f.SetValidateErr(sentinel)
		require.NoError(t, reg.Register(f))
		assert.ErrorIs(t, reg.Validate(providertest.MustParseRef(t, "file:///etc/x")), sentinel)
	})

	t.Run("schemes are sorted", func(t *testing.T) {
		t.Parallel()
		reg := provider.NewRegistry()
		for _, s := range []string{"vault", "file", "aws"} {
			require.NoError(t, reg.Register(providertest.New(s)))
		}
		assert.Equal(t, []string{"aws", "file", "vault"}, reg.Schemes())
	})
}

// Provider.Scheme is documented as "the lowercased URL scheme" and ref.Parse
// lowercases every scheme before lookup. Register stores Scheme() verbatim, so
// a provider registered as "File" or "" is accepted and then unreachable, and a
// nil provider panics instead of erroring.
func TestRegistrySchemeContract(t *testing.T) {
	t.Parallel()

	t.Run("mixed case must be rejected or reachable", func(t *testing.T) {
		t.Parallel()
		reg := provider.NewRegistry()
		if err := reg.Register(providertest.New("File")); err == nil {
			assert.NoError(t, reg.Validate(providertest.MustParseRef(t, "file:///etc/x")),
				"Register accepted %q but no ref can reach it (ref.Parse lowercases)", "File")
		}
	})

	t.Run("empty scheme is rejected", func(t *testing.T) {
		t.Parallel()
		assert.Error(t, provider.NewRegistry().Register(providertest.New("")))
	})

	t.Run("nil provider is rejected without panicking", func(t *testing.T) {
		t.Parallel()
		reg := provider.NewRegistry()
		assert.NotPanics(t, func() { assert.Error(t, reg.Register(nil)) })
	})
}

// The zero-value Registry answers Get/Schemes/Validate like an empty registry
// but panics on Register (nil map), so a forgotten NewRegistry surfaces late.
func TestZeroValueRegistry(t *testing.T) {
	t.Parallel()

	var reg provider.Registry
	_, ok := reg.Get("file")
	require.False(t, ok)
	require.Empty(t, reg.Schemes())
	require.Error(t, reg.Validate(providertest.MustParseRef(t, "file:///etc/x")))

	assert.NotPanics(t, func() {
		_ = reg.Register(providertest.New("file"))
	}, "zero-value Registry: Get/Schemes/Validate work but Register panics")
}

// Registry is documented as shared by config validation and the authorize
// runtime, yet has no synchronization: Register concurrent with Get is a data
// race on the map.
func TestRegistryConcurrentAccess(t *testing.T) {
	// Not parallel: a race report here must not be attributed to unrelated
	// tests running at the same time.
	reg := provider.NewRegistry()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = reg.Register(providertest.New("file"))
	}()
	_, _ = reg.Get("file")
	_ = reg.Schemes()
	wg.Wait()

	_, ok := reg.Get("file")
	assert.True(t, ok)
}

func TestErrorClassification(t *testing.T) {
	t.Parallel()

	assert.True(t, provider.IsNotFound(provider.ErrNotFound))
	assert.True(t, provider.IsNotFound(fmt.Errorf("read %q: %w", "path", provider.ErrNotFound)))
	assert.False(t, provider.IsNotFound(errors.New("connection refused")), "arbitrary errors are transient, not not-found")
	assert.False(t, provider.IsNotFound(nil))
	assert.False(t, provider.IsNotFound(provider.ErrTooLarge), "an oversized secret must never be negative-cached as missing")
}
