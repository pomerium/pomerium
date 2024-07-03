package okta_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oidc/okta"
)

func TestGetOptions(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"https://awesomecompany.okta.com",
		okta.GetOptions(&oauth.Options{ProviderURL: "https://awesomecompany.okta.com/"}).ProviderURL,
		"should trim trailing slash")
}
