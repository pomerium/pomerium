package urlutil

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/hpke"
)

func TestCallbackURL(t *testing.T) {
	t.Parallel()
	k1 := hpke.DerivePrivateKey([]byte("sender"))
	k2 := hpke.DerivePrivateKey([]byte("receiver"))

	rawSignInURL, err := CallbackURL(k1, k2.PublicKey(), url.Values{
		QueryRedirectURI: {"https://redirect.example.com"},
	}, &identity.Profile{
		ProviderId: "IDP-1",
	})
	require.NoError(t, err)

	signInURL, err := ParseAndValidateURL(rawSignInURL)
	require.NoError(t, err)

	k3, q, err := hpke.DecryptURLValues(k2, signInURL.Query())
	require.NoError(t, err)
	assert.Equal(t, k1.PublicKey(), k3)
	assert.NotEmpty(t, q.Get(QueryExpiry))
	assert.NotEmpty(t, q.Get(QueryIssued))
	assert.NotEmpty(t, q.Get(QueryVersion))
	assert.Equal(t, "https://redirect.example.com", q.Get(QueryRedirectURI))
	assert.JSONEq(t, `{ "providerId": "IDP-1" }`, q.Get(QueryIdentityProfile))
}

func TestRedirectURI(t *testing.T) {
	t.Run("query", func(t *testing.T) {
		r, err := http.NewRequest("GET", "https://www.example.com?"+(url.Values{
			QueryRedirectURI: {"https://www.example.com/redirect"},
		}).Encode(), nil)
		require.NoError(t, err)

		redirectURI, ok := RedirectURL(r)
		assert.True(t, ok)
		assert.Equal(t, "https://www.example.com/redirect", redirectURI)
	})
	t.Run("form", func(t *testing.T) {
		r, err := http.NewRequest("POST", "https://www.example.com", strings.NewReader((url.Values{
			QueryRedirectURI: {"https://www.example.com/redirect"},
		}).Encode()))
		require.NoError(t, err)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		redirectURI, ok := RedirectURL(r)
		assert.True(t, ok)
		assert.Equal(t, "https://www.example.com/redirect", redirectURI)
	})
	t.Run("cookie", func(t *testing.T) {
		r, err := http.NewRequest("GET", "https://www.example.com", nil)
		require.NoError(t, err)
		r.AddCookie(&http.Cookie{
			Name:  QueryRedirectURI,
			Value: "https://www.example.com/redirect",
		})

		redirectURI, ok := RedirectURL(r)
		assert.True(t, ok)
		assert.Equal(t, "https://www.example.com/redirect", redirectURI)
	})
}

func TestSignInURL(t *testing.T) {
	t.Parallel()
	k1 := hpke.DerivePrivateKey([]byte("sender"))
	k2 := hpke.DerivePrivateKey([]byte("receiver"))

	authenticateURL := MustParseAndValidateURL("https://authenticate.example.com")
	redirectURL := MustParseAndValidateURL("https://redirect.example.com")

	rawSignInURL, err := SignInURL(k1, k2.PublicKey(), &authenticateURL, &redirectURL, "IDP-1")
	require.NoError(t, err)

	signInURL, err := ParseAndValidateURL(rawSignInURL)
	require.NoError(t, err)

	k3, q, err := hpke.DecryptURLValues(k2, signInURL.Query())
	require.NoError(t, err)
	assert.Equal(t, k1.PublicKey(), k3)
	assert.NotEmpty(t, q.Get(QueryExpiry))
	assert.NotEmpty(t, q.Get(QueryIssued))
	assert.NotEmpty(t, q.Get(QueryVersion))
	assert.Equal(t, "https://redirect.example.com", q.Get(QueryRedirectURI))
	assert.Equal(t, "IDP-1", q.Get(QueryIdentityProviderID))
}

func TestSignOutURL(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest("GET", "https://route.example.com?"+(url.Values{
		QueryRedirectURI: {"https://www.example.com/redirect"},
	}).Encode(), nil)
	authenticateURL := MustParseAndValidateURL("https://authenticate.example.com")

	rawSignOutURL := SignOutURL(r, &authenticateURL, []byte("TEST"))
	signOutURL, err := ParseAndValidateURL(rawSignOutURL)
	require.NoError(t, err)

	q := signOutURL.Query()
	assert.NotEmpty(t, q.Get(QueryExpiry))
	assert.NotEmpty(t, q.Get(QueryIssued))
	assert.NotEmpty(t, q.Get(QueryVersion))
	assert.NotEmpty(t, q.Get(QueryHmacSignature))
	assert.Equal(t, "https://www.example.com/redirect", q.Get(QueryRedirectURI))
}
