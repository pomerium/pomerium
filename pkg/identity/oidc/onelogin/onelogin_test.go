package onelogin_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oidc/onelogin"
)

func TestGetOptions(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"https://openid-connect.onelogin.com/oidc",
		onelogin.GetOptions(&oauth.Options{}).ProviderURL,
		"should set default provider url")
	assert.Equal(t,
		[]string{"openid", "profile", "email", "groups", "offline_access"},
		onelogin.GetOptions(&oauth.Options{ProviderURL: "https://openid-connect.onelogin.com/oidc"}).Scopes,
		"should set default v1 scopes")
	assert.Equal(t,
		[]string{"openid", "profile", "email", "groups"},
		onelogin.GetOptions(&oauth.Options{ProviderURL: "https://openid-connect.onelogin.com/oidc/2"}).Scopes,
		"should set default v2 scopes")
	assert.Equal(t,
		"https://openid-connect.onelogin.com/oidc",
		onelogin.GetOptions(&oauth.Options{ProviderURL: "https://openid-connect.onelogin.com/oidc/"}).ProviderURL,
		"should trim trailing slash")
}
