package identity

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oidc/google"
)

func TestNewAuthenticatorRemovesReservedAuthCodeOptions(t *testing.T) {
	const providerName = "test-reserved-auth-code-options"

	var got map[string]string
	RegisterAuthenticator(providerName, func(_ context.Context, o *oauth.Options) (Authenticator, error) {
		got = o.AuthCodeOptions
		return nil, nil
	})
	t.Cleanup(func() { delete(registry, providerName) })

	requestParams := map[string]string{
		"client_id":             "client_id",
		"Client_ID":             "client_id",
		"response_type":         "response_type",
		"redirect_uri":          "https://example.com/callback",
		"scope":                 "openid",
		"state":                 "state",
		"code_challenge":        "challenge",
		"code_challenge_method": "plain",
		"prompt":                "login",
	}

	_, err := NewAuthenticator(t.Context(), noop.NewTracerProvider(), oauth.Options{
		ProviderName:    providerName,
		AuthCodeOptions: requestParams,
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"prompt": "login"}, got)
	assert.Contains(t, requestParams, "client_id")

	a, err := NewAuthenticator(t.Context(), noop.NewTracerProvider(), oauth.Options{
		ProviderName: google.Name,
		AuthCodeOptions: map[string]string{
			"client_id": "client_id",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"access_type": "offline",
		"prompt":      "select_account consent",
	}, a.(*google.Provider).AuthCodeOptions)
}
