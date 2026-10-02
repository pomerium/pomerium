package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/secrets/file"
	"github.com/pomerium/pomerium/pkg/secrets/provider"
	"github.com/pomerium/pomerium/pkg/secrets/ref"
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

// The default file provider is also a Watcher, and refs round-trip through the
// registry into the real provider's Validate.
func TestDefaultRegistryFileProvider(t *testing.T) {
	t.Parallel()

	reg := DefaultRegistry()
	p, ok := reg.Get("file")
	require.True(t, ok)
	_, isWatcher := p.(provider.Watcher)
	assert.True(t, isWatcher)

	r, err := ref.Parse("file:///etc/x?foo=1")
	require.NoError(t, err)
	assert.Error(t, reg.Validate(r), "provider-specific validation must be reachable via the registry")
}

func TestMustRegisterPanicsOnDuplicate(t *testing.T) {
	t.Parallel()

	reg := DefaultRegistry()
	assert.Panics(t, func() { mustRegister(reg, file.New()) })
}
