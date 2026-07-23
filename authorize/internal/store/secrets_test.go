package store

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/secrets/resolver"
)

type fakeLookup struct{}

func (fakeLookup) View() resolver.View { return nil }

func TestSecretsLookup(t *testing.T) {
	t.Parallel()

	s := New()
	assert.Nil(t, s.GetSecretsLookup(), "nil-safe when never set")

	l := fakeLookup{}
	s.UpdateSecretsLookup(l)
	assert.Equal(t, l, s.GetSecretsLookup())

	// Mirrors the MCP provider: a nil update is a no-op, so the lookup can never
	// be un-set.
	s.UpdateSecretsLookup(nil)
	assert.Equal(t, l, s.GetSecretsLookup())
}
