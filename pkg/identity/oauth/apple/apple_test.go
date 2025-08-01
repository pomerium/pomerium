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
	"golang.org/x/oauth2"

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
	t.Cleanup(srv.Close)

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

func TestRefresh_WithIDToken(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwtSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, nil)
	require.NoError(t, err)
	iat := time.Now()
	exp := iat.Add(time.Hour)

	newIDToken, err := jwt.Signed(jwtSigner).Claims(jwt.Claims{
		Subject:  "USER_ID",
		Audience: jwt.Audience{"CLIENT_ID"},
		Expiry:   jwt.NewNumericDate(exp),
		IssuedAt: jwt.NewNumericDate(iat),
	}).CompactSerialize()
	require.NoError(t, err)

	m := http.NewServeMux()
	m.HandleFunc("POST /auth/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "refreshed-access-token",
			"id_token":     newIDToken,
		})
	})
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)

	p, err := apple.New(t.Context(), &oauth.Options{
		ProviderURL:  srv.URL,
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		RedirectURL:  urlutil.MustParseAndValidateURL("https://www.example.com"),
	})
	require.NoError(t, err)

	token := oauth2.Token{
		AccessToken:  "original-access-token",
		RefreshToken: "original-refresh-token",
	}
	var claims Claims
	newToken, err := p.Refresh(t.Context(), &token, &claims)
	assert.NoError(t, err)
	assert.Equal(t, "refreshed-access-token", newToken.AccessToken)
	assert.Equal(t, newIDToken, claims["RawIDToken"])
	assert.Equal(t, "USER_ID", claims["sub"])
	assert.Equal(t, "CLIENT_ID", claims["aud"])
	assert.Equal(t, float64(iat.Unix()), claims["iat"])
	assert.Equal(t, float64(exp.Unix()), claims["exp"])
}

func TestRefresh_WithoutIDToken(t *testing.T) {
	t.Parallel()

	m := http.NewServeMux()
	m.HandleFunc("POST /auth/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "refreshed-access-token",
		})
	})
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)

	p, err := apple.New(t.Context(), &oauth.Options{
		ProviderURL:  srv.URL,
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		RedirectURL:  urlutil.MustParseAndValidateURL("https://www.example.com"),
	})
	require.NoError(t, err)

	token := oauth2.Token{
		AccessToken:  "original-access-token",
		RefreshToken: "original-refresh-token",
	}
	var claims Claims
	claims.SetRawIDToken("original-id-token") // verify that any existing ID token is cleared
	newToken, err := p.Refresh(t.Context(), &token, &claims)
	assert.NoError(t, err)
	assert.Equal(t, "refreshed-access-token", newToken.AccessToken)
	assert.Empty(t, claims)
}

// Claims implements identity.State. (We can't use identity.Claims directly
// because it would cause an import cycle.)
type Claims map[string]any

func (c *Claims) SetRawIDToken(idToken string) {
	if *c == nil {
		*c = make(map[string]any)
	}
	if idToken != "" {
		(*c)["RawIDToken"] = idToken
	} else {
		delete((*c), "RawIDToken")
	}
}
