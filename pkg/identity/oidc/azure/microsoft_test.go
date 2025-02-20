package azure

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/identity/identity"
	"github.com/pomerium/pomerium/pkg/identity/oauth"
)

func TestAuthCodeOptions(t *testing.T) {
	t.Parallel()

	var options oauth.Options
	p, err := New(context.Background(), &options)
	require.NoError(t, err)
	assert.Equal(t, defaultAuthCodeOptions, p.AuthCodeOptions)

	options.AuthCodeOptions = map[string]string{}
	p, err = New(context.Background(), &options)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{}, p.AuthCodeOptions)
}

func TestVerifyAccessToken(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, time.Minute)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwtSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, nil)
	require.NoError(t, err)
	iat := time.Now().Unix()
	exp := iat + 3600
	rawAccessToken1, err := jwt.Signed(jwtSigner).Claims(map[string]any{
		"iss": "https://sts.windows.net/323b4000-7ad7-4ed3-9f4e-adee06ee8bbe/",
		"aud": "https://client.example.com",
		"sub": "subject",
		"exp": exp,
		"iat": iat,
	}).CompactSerialize()
	require.NoError(t, err)
	rawAccessToken2, err := jwt.Signed(jwtSigner).Claims(map[string]any{
		"iss": "https://sts.windows.net/323b4000-7ad7-4ed3-9f4e-adee06ee8bbe/",
		"aud": "https://unexpected.example.com",
		"sub": "subject",
		"exp": exp,
		"iat": iat,
	}).CompactSerialize()
	require.NoError(t, err)

	var srvURL string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srvURL,
			"authorization_endpoint":                srvURL + "/auth",
			"token_endpoint":                        "https://sts.windows.net/323b4000-7ad7-4ed3-9f4e-adee06ee8bbe/token",
			"jwks_uri":                              srvURL + "/keys",
			"id_token_signing_alg_values_supported": []any{"RS256"},
		})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{Key: privateKey.Public(), Use: "sig", Algorithm: "RS256"},
			},
		})
	})
	srv := httptest.NewServer(mux)
	srvURL = srv.URL

	audiences := []string{"https://other.example.com", "https://client.example.com"}
	p, err := New(ctx, &oauth.Options{
		ProviderName:                Name,
		ProviderURL:                 srv.URL,
		ClientID:                    "CLIENT_ID",
		ClientSecret:                "CLIENT_SECRET",
		AccessTokenAllowedAudiences: &audiences,
	})
	require.NoError(t, err)

	claims, err := p.VerifyAccessToken(ctx, rawAccessToken1)
	require.NoError(t, err)
	delete(claims, "iat")
	delete(claims, "exp")
	assert.Equal(t, map[string]any{
		"iss": "https://sts.windows.net/323b4000-7ad7-4ed3-9f4e-adee06ee8bbe/",
		"aud": "https://client.example.com",
		"sub": "subject",
	}, claims)

	_, err = p.VerifyAccessToken(ctx, rawAccessToken2)
	assert.ErrorContains(t, err, "invalid audience")
}

func TestVerifyIdentityToken(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, time.Minute)

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)

	p, err := New(ctx, &oauth.Options{
		ProviderName: Name,
		ProviderURL:  srv.URL,
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
	})
	require.NoError(t, err)

	claims, err := p.VerifyIdentityToken(ctx, "RAW IDENTITY TOKEN")
	assert.ErrorIs(t, identity.ErrVerifyIdentityTokenNotSupported, err)
	assert.Nil(t, claims)
}
