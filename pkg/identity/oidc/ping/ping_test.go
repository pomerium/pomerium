package ping_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oidc/ping"
)

func TestGetOptions(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"https://www.example.com",
		ping.GetOptions(&oauth.Options{ProviderURL: "https://www.example.com/"}).ProviderURL,
		"should trim trailing slash")
}
