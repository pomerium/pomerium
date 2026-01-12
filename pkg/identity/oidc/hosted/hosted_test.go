package hosted

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/pkg/identity/oauth"
)

var exampleOptions = &oauth.Options{
	ProviderURL:  "https://example.com",
	ClientID:     "https://my-client.example.com",
	ClientSecret: strings.Repeat("A", 86), // base64 encoding of 64 bytes of zeros
}

func TestNew(t *testing.T) {
	t.Run("invalid key", func(t *testing.T) {
		_, err := New(t.Context(), &oauth.Options{
			ClientSecret: "not!valid!base64",
		})
		assert.ErrorContains(t, err, "invalid client secret")
	})
	t.Run("invalid key length", func(t *testing.T) {
		_, err := New(t.Context(), &oauth.Options{})
		assert.ErrorContains(t, err, "invalid Ed25519 private key")
	})
	t.Run("ok", func(t *testing.T) {
		_, err := New(t.Context(), exampleOptions)
		assert.NoError(t, err)
	})
}

func TestSignIn(t *testing.T) {
	var srv *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL, err := url.Parse(srv.URL)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer": baseURL.String(),
				"authorization_endpoint": baseURL.ResolveReference(&url.URL{
					Path: "/login",
				}).String(),
			})
		default:
			assert.Failf(t, "unexpected http request", "url: %s", r.URL.String())
		}
	})
	srv = httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	pub, priv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	p, _ := New(t.Context(), &oauth.Options{
		ProviderURL:  srv.URL,
		ClientID:     "https://my-client.example.com",
		ClientSecret: base64.RawStdEncoding.EncodeToString(priv),
		RedirectURL: &url.URL{
			Scheme: "https",
			Host:   "my-client.example.com",
			Path:   "/oauth2/callback",
		},
	})
	// Set a known fake version string.
	p.pomeriumVersion = "0.31.0+abcdefg darwin/arm64"

	rec := httptest.NewRecorder()
	err = p.SignIn(rec, httptest.NewRequest(http.MethodGet, "/", nil), "STATE")
	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, rec.Result().StatusCode)
	location, _ := url.Parse(rec.Result().Header.Get("Location"))
	assert.Equal(t, srv.URL, "http://"+location.Host)
	assert.Equal(t, "/login", location.Path)
	q := location.Query()
	assert.Len(t, q, 1)
	requestJWT, err := jwt.ParseSigned(q.Get("request"))
	require.NoError(t, err)
	var claims struct {
		jwt.Claims
		ClientID        string `json:"client_id"`
		PomeriumVersion string `json:"pomerium_version"`
		RedirectURI     string `json:"redirect_uri"`
		ResponseType    string `json:"response_type"`
		Scope           string `json:"scope"`
		State           string `json:"state"`
	}
	err = requestJWT.Claims(pub, &claims)
	require.NoError(t, err)
	err = claims.Validate(jwt.Expected{
		Issuer:   claims.ClientID,
		Audience: jwt.Audience{srv.URL},
	})
	require.NoError(t, err)
	assert.Equal(t, "https://my-client.example.com", claims.ClientID)
	assert.Equal(t, "0.31.0+abcdefg darwin/arm64", claims.PomeriumVersion)
	assert.Equal(t, "https://my-client.example.com/oauth2/callback", claims.RedirectURI)
	assert.Equal(t, "code", claims.ResponseType)
	assert.Equal(t, "openid profile email offline_access", claims.Scope)
	assert.Equal(t, "STATE", claims.State)
}

func TestAuthenticate(t *testing.T) {
	// Client's JWT assertion signing key.
	clientPub, clientPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Provider's ID token signing key.
	providerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: providerPriv.Public()}},
	}
	providerSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: providerPriv}, nil)
	require.NoError(t, err)

	var expectedIDToken string

	var srv *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL, err := url.Parse(srv.URL)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer":            baseURL.String(),
				"jwks_uri":          baseURL.ResolveReference(&url.URL{Path: "/jwks"}).String(),
				"token_endpoint":    baseURL.ResolveReference(&url.URL{Path: "/token"}).String(),
				"userinfo_endpoint": baseURL.ResolveReference(&url.URL{Path: "/userinfo"}).String(),

				"id_token_signing_alg_values_supported": []string{"ES256"},
			})
		case "/jwks":
			json.NewEncoder(w).Encode(jwks)
		case "/token":
			// Verify no client_secret is present.
			_, secret, _ := r.BasicAuth()
			assert.Empty(t, secret)
			assert.Empty(t, r.FormValue("client_secret"))

			// Verify the private_key_jwt client auth.
			assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
				r.FormValue("client_assertion_type"))
			clientJWT, err := jwt.ParseSigned(r.FormValue("client_assertion"))
			require.NoError(t, err)
			var claims struct {
				jwt.Claims
				PomeriumVersion string `json:"pomerium_version"`
			}
			clientJWT.Claims(clientPub, &claims)
			claims.Validate(jwt.Expected{
				Issuer:   "https://my-client.example.com",
				Subject:  "https://my-client.example.com",
				Audience: jwt.Audience{srv.URL + "/token"},
			})
			assert.Equal(t, "0.31.0+abcdefg darwin/arm64", claims.PomeriumVersion)

			assert.Equal(t, "authorization_code", r.FormValue("grant_type"))
			assert.Equal(t, "CODE", r.FormValue("code"))

			// Construct a valid ID token.
			idToken, err := jwt.Signed(providerSigner).Claims(jwt.Claims{
				Issuer:   srv.URL,
				Subject:  "USER_ID",
				Audience: jwt.Audience{"https://my-client.example.com"},
				Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			}).CompactSerialize()
			require.NoError(t, err)
			expectedIDToken = idToken

			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "ACCESS_TOKEN",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"id_token":     idToken,
			})
		case "/userinfo":
			assert.Equal(t, "Bearer ACCESS_TOKEN", r.Header.Get("Authorization"))

			json.NewEncoder(w).Encode(map[string]any{
				"sub":   "USER_ID",
				"name":  "John Doe",
				"email": "john.doe@example.com",
			})
		default:
			assert.Failf(t, "unexpected http request", "url: %s", r.URL.String())
		}
	})
	srv = httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	p, _ := New(t.Context(), &oauth.Options{
		ProviderURL:  srv.URL,
		ClientID:     "https://my-client.example.com",
		ClientSecret: base64.RawStdEncoding.EncodeToString(clientPriv),
		RedirectURL: &url.URL{
			Scheme: "https",
			Host:   "my-client.example.com",
			Path:   "/oauth2/callback",
		},
	})
	// Set a known fake version string.
	p.pomeriumVersion = "0.31.0+abcdefg darwin/arm64"

	var claims Claims
	token, err := p.Authenticate(t.Context(), "CODE", &claims)
	require.NoError(t, err)
	assert.Equal(t, expectedIDToken, claims.rawIDToken)
	assert.Equal(t, "ACCESS_TOKEN", token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.Equal(t, int64(3600), token.ExpiresIn)
}

func TestRefresh(t *testing.T) {
	// Client's JWT assertion signing key.
	clientPub, clientPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Provider's ID token signing key.
	providerPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{Key: providerPriv.Public()}},
	}
	providerSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: providerPriv}, nil)
	require.NoError(t, err)

	var expectedIDToken string

	var srv *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL, err := url.Parse(srv.URL)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer":            baseURL.String(),
				"jwks_uri":          baseURL.ResolveReference(&url.URL{Path: "/jwks"}).String(),
				"token_endpoint":    baseURL.ResolveReference(&url.URL{Path: "/token"}).String(),
				"userinfo_endpoint": baseURL.ResolveReference(&url.URL{Path: "/userinfo"}).String(),

				"id_token_signing_alg_values_supported": []string{"ES256"},
			})
		case "/jwks":
			json.NewEncoder(w).Encode(jwks)
		case "/token":
			// Verify no client_secret is present.
			_, secret, _ := r.BasicAuth()
			assert.Empty(t, secret)
			assert.Empty(t, r.FormValue("client_secret"))

			// Verify the private_key_jwt client auth.
			assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
				r.FormValue("client_assertion_type"))
			clientJWT, err := jwt.ParseSigned(r.FormValue("client_assertion"))
			require.NoError(t, err)
			var claims struct {
				jwt.Claims
				PomeriumVersion string `json:"pomerium_version"`
			}
			clientJWT.Claims(clientPub, &claims)
			claims.Validate(jwt.Expected{
				Issuer:   "https://my-client.example.com",
				Subject:  "https://my-client.example.com",
				Audience: jwt.Audience{srv.URL + "/token"},
			})
			assert.Equal(t, "0.31.0+abcdefg darwin/arm64", claims.PomeriumVersion)

			assert.Equal(t, "refresh_token", r.FormValue("grant_type"))
			assert.Equal(t, "ORIGINAL_REFRESH_TOKEN", r.FormValue("refresh_token"))

			// Construct a valid ID token.
			idToken, err := jwt.Signed(providerSigner).Claims(jwt.Claims{
				Issuer:   srv.URL,
				Subject:  "USER_ID",
				Audience: jwt.Audience{"https://my-client.example.com"},
				Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			}).CompactSerialize()
			require.NoError(t, err)
			expectedIDToken = idToken

			json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "ACCESS_TOKEN",
				"refresh_token": "NEW_REFRESH_TOKEN",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"id_token":      idToken,
			})
		case "/userinfo":
			assert.Equal(t, "Bearer ACCESS_TOKEN", r.Header.Get("Authorization"))

			json.NewEncoder(w).Encode(map[string]any{
				"sub":   "USER_ID",
				"name":  "John Doe",
				"email": "john.doe@example.com",
			})
		default:
			assert.Failf(t, "unexpected http request", "url: %s", r.URL.String())
		}
	})
	srv = httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	p, _ := New(t.Context(), &oauth.Options{
		ProviderURL:  srv.URL,
		ClientID:     "https://my-client.example.com",
		ClientSecret: base64.RawStdEncoding.EncodeToString(clientPriv),
		RedirectURL: &url.URL{
			Scheme: "https",
			Host:   "my-client.example.com",
			Path:   "/oauth2/callback",
		},
	})
	// Set a known fake version string.
	p.pomeriumVersion = "0.31.0+abcdefg darwin/arm64"

	var claims Claims
	token, err := p.Refresh(t.Context(), &oauth2.Token{
		RefreshToken: "ORIGINAL_REFRESH_TOKEN",
	}, &claims)
	require.NoError(t, err)
	assert.Equal(t, expectedIDToken, claims.rawIDToken)
	assert.Equal(t, "ACCESS_TOKEN", token.AccessToken)
	assert.Equal(t, "NEW_REFRESH_TOKEN", token.RefreshToken)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.Equal(t, int64(3600), token.ExpiresIn)
}

func TestName(t *testing.T) {
	p, _ := New(t.Context(), exampleOptions)
	assert.Equal(t, "hosted", p.Name())
}

type Claims struct {
	claims     map[string]any
	rawIDToken string
}

func (c *Claims) SetRawIDToken(rawIDToken string) {
	c.rawIDToken = rawIDToken
}

func (c *Claims) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &c.claims)
}
