package urlutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsHostedAuthenticateDomain(t *testing.T) {
	t.Parallel()

	for _, domain := range HostedAuthenticateDomains {
		assert.True(t, IsHostedAuthenticateDomain(domain), domain)
	}

	for _, domain := range []string{"authenticate.example.com", "foo.bar"} {
		assert.False(t, IsHostedAuthenticateDomain(domain), domain)
	}
}
