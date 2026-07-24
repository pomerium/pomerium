package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultRegistry(t *testing.T) {
	t.Parallel()

	reg := DefaultRegistry()
	assert.Equal(t, []string{"file"}, reg.Schemes())

	// Independent instances with identical scheme sets: config validation and
	// the authorize runtime each construct their own but must agree on schemes.
	other := DefaultRegistry()
	assert.Equal(t, reg.Schemes(), other.Schemes())
	assert.NotSame(t, reg, other)
}
