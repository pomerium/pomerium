package apple_test

import (
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
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oauth/apple"
)

func TestVerifyIdentityToken(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, time.Minute)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwtSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, nil)
	require.NoError(t, err)
	iat := time.Now().Unix()
	exp := iat + 3600

	m := http.NewServeMux()
	m.HandleFunc("GET /auth/keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{Key: privateKey.Public(), Use: "sig", Algorithm: "RS256"},
			},
		})
	})
	srv := httptest.NewServer(m)

	rawIdentityToken1, err := jwt.Signed(jwtSigner).Claims(map[string]any{
		"iss": srv.URL,
		"aud": "CLIENT_ID",
		"sub": "subject",
		"exp": exp,
		"iat": iat,
	}).CompactSerialize()
	require.NoError(t, err)

	p, err := apple.New(ctx, &oauth.Options{
		ProviderURL:  srv.URL,
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		RedirectURL:  urlutil.MustParseAndValidateURL("https://www.example.com"),
	})
	require.NoError(t, err)

	claims, err := p.VerifyIdentityToken(ctx, rawIdentityToken1)
	require.NoError(t, err)
	delete(claims, "iat")
	delete(claims, "exp")
	assert.Equal(t, map[string]any{
		"aud": "CLIENT_ID",
		"iss": srv.URL,
		"sub": "subject",
	}, claims)
}
