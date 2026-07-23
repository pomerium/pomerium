package bindings_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/secrets/bindings"
	"github.com/pomerium/pomerium/pkg/secrets/provider"
	"github.com/pomerium/pomerium/pkg/secrets/provider/providertest"
	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

func testRegistry(t *testing.T) *provider.Registry {
	t.Helper()
	reg := provider.NewRegistry()
	require.NoError(t, reg.Register(providertest.New("file")))
	return reg
}

func mustRef(t *testing.T, raw string) ref.Ref {
	t.Helper()
	r, err := ref.Parse(raw)
	require.NoError(t, err)
	return r
}

func stdDefaults() bindings.Defaults {
	return bindings.Defaults{
		Refresh:     bindings.DefaultRefresh,
		StaleGrace:  bindings.DefaultStaleGrace,
		NegativeTTL: bindings.DefaultNegativeTTL,
	}
}

func TestBindingIDCharset(t *testing.T) {
	t.Parallel()

	valid := []string{"upstream-api-token", "a", "_x9", "A_b-9"}
	invalid := []string{"", "-x", "a.b", "a b", "a:b", "ünıcode"}

	reg := testRegistry(t)

	for _, id := range valid {
		t.Run("valid/"+id, func(t *testing.T) {
			t.Parallel()
			_, err := bindings.NewScope(nil, []bindings.Binding{{ID: id, Ref: mustRef(t, "file:///etc/x")}}, stdDefaults(), reg)
			assert.NoError(t, err)
		})
	}
	for _, id := range invalid {
		t.Run("invalid/"+id, func(t *testing.T) {
			t.Parallel()
			_, err := bindings.NewScope(nil, []bindings.Binding{{ID: id, Ref: mustRef(t, "file:///etc/x")}}, stdDefaults(), reg)
			require.Error(t, err)
			if id != "" {
				assert.Contains(t, err.Error(), id, "error should name the offending ID")
			}
		})
	}
}

func TestBindingValidate(t *testing.T) {
	t.Parallel()

	reg := testRegistry(t)

	t.Run("valid binding", func(t *testing.T) {
		t.Parallel()
		_, err := bindings.NewScope(nil, []bindings.Binding{{ID: "tok", Ref: mustRef(t, "file:///etc/x")}}, stdDefaults(), reg)
		assert.NoError(t, err)
	})

	t.Run("unknown scheme rejected by registry", func(t *testing.T) {
		t.Parallel()
		_, err := bindings.NewScope(nil, []bindings.Binding{{ID: "tok", Ref: mustRef(t, "vault:///secret/data/x")}}, stdDefaults(), reg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tok")
	})

	t.Run("refresh below floor", func(t *testing.T) {
		t.Parallel()
		_, err := bindings.NewScope(nil, []bindings.Binding{{ID: "tok", Ref: mustRef(t, "file:///etc/x"), Refresh: 500 * time.Millisecond}}, stdDefaults(), reg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tok")
	})

	t.Run("negative stale_grace", func(t *testing.T) {
		t.Parallel()
		_, err := bindings.NewScope(nil, []bindings.Binding{{ID: "tok", Ref: mustRef(t, "file:///etc/x"), StaleGrace: -time.Second}}, stdDefaults(), reg)
		require.Error(t, err)
	})

	t.Run("interpolation in URL never forms a binding", func(t *testing.T) {
		t.Parallel()
		_, err := ref.Parse("file:///etc/x${y}")
		assert.Error(t, err, "a ${...} URL is rejected at parse, so it can never reach NewScope")
	})
}

func TestScopeResolve(t *testing.T) {
	t.Parallel()

	reg := testRegistry(t)

	t.Run("root exact match", func(t *testing.T) {
		t.Parallel()
		s, err := bindings.NewScope(nil, []bindings.Binding{{ID: "a", Ref: mustRef(t, "file:///a")}}, stdDefaults(), reg)
		require.NoError(t, err)

		got, ok := s.Resolve("a")
		require.True(t, ok)
		assert.Equal(t, "file:///a", got.Ref.Key())

		_, ok = s.Resolve("missing")
		assert.False(t, ok)
	})

	t.Run("child shadows parent, leaf wins", func(t *testing.T) {
		t.Parallel()
		parent, err := bindings.NewScope(nil, []bindings.Binding{
			{ID: "shared", Ref: mustRef(t, "file:///parent")},
			{ID: "only-parent", Ref: mustRef(t, "file:///p")},
		}, stdDefaults(), reg)
		require.NoError(t, err)

		child, err := bindings.NewScope(parent, []bindings.Binding{
			{ID: "shared", Ref: mustRef(t, "file:///child")},
			{ID: "only-child", Ref: mustRef(t, "file:///c")},
		}, stdDefaults(), reg)
		require.NoError(t, err)

		shared, ok := child.Resolve("shared")
		require.True(t, ok)
		assert.Equal(t, "file:///child", shared.Ref.Key(), "leaf wins")

		parentOnly, ok := child.Resolve("only-parent")
		require.True(t, ok)
		assert.Equal(t, "file:///p", parentOnly.Ref.Key(), "resolves from parent")

		childOnly, ok := child.Resolve("only-child")
		require.True(t, ok)
		assert.Equal(t, "file:///c", childOnly.Ref.Key())

		_, ok = child.Resolve("nowhere")
		assert.False(t, ok)
	})
}

func TestScopeDuplicateWithinLevel(t *testing.T) {
	t.Parallel()

	reg := testRegistry(t)
	_, err := bindings.NewScope(nil, []bindings.Binding{
		{ID: "dup", Ref: mustRef(t, "file:///a")},
		{ID: "dup", Ref: mustRef(t, "file:///b")},
	}, stdDefaults(), reg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dup")
}

func TestDefaultsApplied(t *testing.T) {
	t.Parallel()

	reg := testRegistry(t)
	s, err := bindings.NewScope(nil, []bindings.Binding{{ID: "tok", Ref: mustRef(t, "file:///a")}}, stdDefaults(), reg)
	require.NoError(t, err)

	b, ok := s.Resolve("tok")
	require.True(t, ok)
	assert.Equal(t, bindings.DefaultRefresh, b.Refresh)
	assert.Equal(t, bindings.DefaultStaleGrace, b.StaleGrace)
	assert.Equal(t, bindings.DefaultNegativeTTL, b.NegativeTTL)
	assert.Equal(t, "tok", b.MetricLabel, "metric label defaults to ID")
}
