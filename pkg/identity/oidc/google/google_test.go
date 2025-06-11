package google

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/identity/oauth"
)

func TestAuthCodeOptions(t *testing.T) {
	var options oauth.Options
	p, err := New(t.Context(), &options)
	require.NoError(t, err)
	assert.Equal(t, defaultAuthCodeOptions, p.AuthCodeOptions)

	options.AuthCodeOptions = map[string]string{}
	p, err = New(t.Context(), &options)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{}, p.AuthCodeOptions)
}
