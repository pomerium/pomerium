package config

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/identity"
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

func TestHostedAuthenticateDerivedCredentials(t *testing.T) {
	// The credentials for hosted authenticate should be derived from the shared
	// secret deterministically.
	sharedSecret := []byte("12345678901234567890123456789012")

	opts := &Options{
		AuthenticateURLString: "https://authenticate.example.com",
		Provider:              "hosted",
		SharedKey:             base64.StdEncoding.EncodeToString(sharedSecret),
	}
	idp, err := opts.GetIdentityProviderForPolicy(nil)

	expectedClientSecret, _ := base64.StdEncoding.DecodeString(
		"dR0xnpwDSEWtwK/Gve7jL/u0p/ja3j4oW0i83AtdrJe28XFBWG8BQT5cqn11fzBUJqwkY9SBei/DTpo1FxvOAw==")

	require.NoError(t, err)
	testutil.AssertProtoEqual(t, &identity.Provider{
		Id:                     "YessfRlH8f2seIb7el8qxaj6RaWbz7CtEILzMtvOZT5D",
		AuthenticateServiceUrl: "https://authenticate.example.com",
		ClientId:               "https://authenticate.example.com",
		ClientSecret:           string(expectedClientSecret),
		Type:                   "hosted",
	}, idp)
}
