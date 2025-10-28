package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/identity/oidc"
)

func TestOptions_GetIdentityProviderForPolicy(t *testing.T) {
	exampleScopes := []string{"scope1", "scope2", "scope3"}
	exampleRequestParams := map[string]string{"extra-param": "param-value"}
	exampleAccessTokenAllowedAudiences := []string{"audience1", "audience2"}
	opts := &Options{
		AuthenticateURLString:          "https://authenticate.example.com",
		ClientID:                       "client-id",
		ClientSecret:                   "client-secret",
		Provider:                       oidc.Name,
		ProviderURL:                    "https://my-idp.example.com",
		Scopes:                         exampleScopes,
		RequestParams:                  exampleRequestParams,
		IDPAccessTokenAllowedAudiences: &exampleAccessTokenAllowedAudiences,
	}
	idp, err := opts.GetIdentityProviderForPolicy(nil)
	require.NoError(t, err)

	assert.Equal(t, "https://authenticate.example.com", idp.AuthenticateServiceUrl)
	assert.Equal(t, "client-id", idp.ClientId)
	assert.Equal(t, "client-secret", idp.ClientSecret)
	assert.Equal(t, oidc.Name, idp.Type)
	assert.Equal(t, "https://my-idp.example.com", idp.Url)
	assert.Equal(t, exampleScopes, idp.Scopes)
	assert.Equal(t, exampleRequestParams, idp.RequestParams)
	assert.Equal(t, exampleAccessTokenAllowedAudiences, idp.AccessTokenAllowedAudiences.GetValues())

	// If a Policy is provided, it may override the client credentials and
	// access token allowed audiences.
	perPolicyAccessTokenAllowedAudiences := []string{"per-policy-allowed-audience"}
	idp, err = opts.GetIdentityProviderForPolicy(&Policy{
		IDPClientID:                    "per-policy-client-id",
		IDPClientSecret:                "per-policy-client-secret",
		IDPAccessTokenAllowedAudiences: &perPolicyAccessTokenAllowedAudiences,
	})
	require.NoError(t, err)

	assert.Equal(t, "https://authenticate.example.com", idp.AuthenticateServiceUrl)
	assert.Equal(t, "per-policy-client-id", idp.ClientId)
	assert.Equal(t, "per-policy-client-secret", idp.ClientSecret)
	assert.Equal(t, oidc.Name, idp.Type)
	assert.Equal(t, "https://my-idp.example.com", idp.Url)
	assert.Equal(t, exampleScopes, idp.Scopes)
	assert.Equal(t, exampleRequestParams, idp.RequestParams)
	assert.Equal(t, perPolicyAccessTokenAllowedAudiences, idp.AccessTokenAllowedAudiences.GetValues())
}
