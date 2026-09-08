package provider

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

// stubProvider is a minimal Provider for registry tests.
type stubProvider struct {
	scheme      string
	validateErr error
}

func (s stubProvider) Scheme() string         { return s.scheme }
func (s stubProvider) Validate(ref.Ref) error { return s.validateErr }
func (stubProvider) Fetch(context.Context, ref.Ref) (Result, error) {
	return Result{}, nil
}

func mustParse(t *testing.T, raw string) ref.Ref {
	t.Helper()
	r, err := ref.Parse(raw)
	require.NoError(t, err)
	return r
}

func TestRegistry(t *testing.T) {
	t.Parallel()

	t.Run("register enables validation", func(t *testing.T) {
		t.Parallel()
		reg := NewRegistry()
		require.NoError(t, reg.Register(stubProvider{scheme: "file"}))

		assert.NoError(t, reg.Validate(mustParse(t, "file:///etc/x")))

		p, ok := reg.Get("file")
		assert.True(t, ok)
		assert.Equal(t, "file", p.Scheme())
		assert.Equal(t, []string{"file"}, reg.Schemes())
	})

	t.Run("unknown scheme names scheme and known set", func(t *testing.T) {
		t.Parallel()
		reg := NewRegistry()
		require.NoError(t, reg.Register(stubProvider{scheme: "file"}))

		err := reg.Validate(mustParse(t, "vault:///secret/data/x"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "vault")
		assert.Contains(t, err.Error(), "file")
	})

	t.Run("duplicate registration is an error", func(t *testing.T) {
		t.Parallel()
		reg := NewRegistry()
		require.NoError(t, reg.Register(stubProvider{scheme: "file"}))
		err := reg.Register(stubProvider{scheme: "file"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "file")
	})

	t.Run("validate delegates to provider", func(t *testing.T) {
		t.Parallel()
		reg := NewRegistry()
		sentinel := errors.New("bad param")
		require.NoError(t, reg.Register(stubProvider{scheme: "file", validateErr: sentinel}))
		assert.ErrorIs(t, reg.Validate(mustParse(t, "file:///etc/x")), sentinel)
	})
}

func TestErrorClassification(t *testing.T) {
	t.Parallel()

	assert.True(t, IsNotFound(ErrNotFound))
	assert.True(t, IsNotFound(fmt.Errorf("read %q: %w", "path", ErrNotFound)))
	assert.False(t, IsNotFound(errors.New("connection refused")), "arbitrary errors are transient, not not-found")
	assert.False(t, IsNotFound(nil))
}
