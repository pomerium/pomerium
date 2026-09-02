package mcp

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The metadata document path negotiates private_key_jwt; dynamic registration
// does not offer it, so a registration asking for it must be refused rather
// than issued a secret it cannot use and a JWKS it will never be able to fetch.
func TestDynamicRegistrationRejectsPrivateKeyJWT(t *testing.T) {
	t.Parallel()

	_, err := createClientRegistrationFromMetadata([]byte(`{
		"redirect_uris": ["https://client.example.com/callback"],
		"token_endpoint_auth_method": "private_key_jwt",
		"jwks_uri": "https://client.example.com/jwks.json"
	}`))
	assert.ErrorContains(t, err, "private_key_jwt")
}

// A client secret is only meaningful for the methods that present one.
func TestDynamicRegistrationIssuesSecretsOnlyForSecretMethods(t *testing.T) {
	t.Parallel()

	for method, wantSecret := range map[string]bool{
		"client_secret_basic": true,
		"client_secret_post":  true,
		"none":                false,
	} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			reg, err := createClientRegistrationFromMetadata(fmt.Appendf(nil, `{
				"redirect_uris": ["https://client.example.com/callback"],
				"token_endpoint_auth_method": %q
			}`, method))
			require.NoError(t, err)
			assert.Equal(t, wantSecret, reg.GetClientSecret() != nil)
		})
	}
}
