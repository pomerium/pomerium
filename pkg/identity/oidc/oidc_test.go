package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oidc"
)

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

func TestSignIn(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Second*10)
	t.Cleanup(clearTimeout)

	redirectURL, _ := url.Parse("https://localhost/oauth2/callback")

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

	p, err := oidc.New(ctx, &oauth.Options{
		ProviderURL:  srv.URL,
		RedirectURL:  redirectURL,
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		AuthCodeOptions: map[string]string{
			"custom_1": "foo",
			"custom_2": "bar",
		},
	})
	require.NoError(t, err)
	require.NotNil(t, p)

	rec := httptest.NewRecorder()
	err = p.SignIn(rec, httptest.NewRequest(http.MethodGet, "/", nil), "STATE")
	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, rec.Result().StatusCode)
	location, _ := url.Parse(rec.Result().Header.Get("Location"))
	assert.Equal(t, srv.URL, "http://"+location.Host)
	assert.Equal(t, "/login", location.Path)
	assert.Equal(t, url.Values{
		"client_id":     {"CLIENT_ID"},
		"custom_1":      {"foo"},
		"custom_2":      {"bar"},
		"redirect_uri":  {"https://localhost/oauth2/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile email offline_access"},
		"state":         {"STATE"},
	}, location.Query())
}

func TestSignOut(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Second*10)
	t.Cleanup(clearTimeout)

	redirectURL, _ := url.Parse("https://localhost/oauth2/callback")

	var srv *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL, err := url.Parse(srv.URL)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer": baseURL.String(),
				"end_session_endpoint": baseURL.ResolveReference(&url.URL{
					Path: "/logout",
				}).String(),
				"frontchannel_logout_supported": true,
			})
		default:
			assert.Failf(t, "unexpected http request", "url: %s", r.URL.String())
		}
	})
	srv = httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	p, err := oidc.New(ctx, &oauth.Options{
		ProviderURL:  srv.URL,
		RedirectURL:  redirectURL,
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
	})
	require.NoError(t, err)
	require.NotNil(t, p)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	err = p.SignOut(rec, r, "ID_TOKEN", "", "https://localhost/redirect")
	require.NoError(t, err)
	assert.Equal(t, http.StatusFound, rec.Result().StatusCode)
	location, _ := url.Parse(rec.Result().Header.Get("Location"))
	assert.Equal(t, srv.URL, "http://"+location.Host)
	assert.Equal(t, "/logout", location.Path)
	assert.Equal(t, url.Values{
		"client_id":                {"CLIENT_ID"},
		"id_token_hint":            {"ID_TOKEN"},
		"post_logout_redirect_uri": {"https://localhost/redirect"},
	}, location.Query())
}

func TestAuthenticate(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Second*10)
	t.Cleanup(clearTimeout)

	redirectURL, _ := url.Parse("https://localhost/oauth2/callback")

	jwtSigner, jwks := setupJWTSigning(t)
	iat := time.Now()
	exp := iat.Add(time.Hour)
	jti := uuid.NewString()

	var expectedIDToken string

	var srv *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL, err := url.Parse(srv.URL)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer": baseURL.String(),
				"jwks_uri": baseURL.ResolveReference(&url.URL{
					Path: "/jwks",
				}).String(),
				"token_endpoint": baseURL.ResolveReference(&url.URL{
					Path: "/token",
				}).String(),
				"userinfo_endpoint": baseURL.ResolveReference(&url.URL{
					Path: "/userinfo",
				}).String(),
			})
		case "/jwks":
			json.NewEncoder(w).Encode(jwks)
		case "/token":
			username, password, _ := r.BasicAuth()
			assert.Equal(t, "CLIENT_ID", username)
			assert.Equal(t, "CLIENT_SECRET", password)
			assert.Equal(t, "authorization_code", r.FormValue("grant_type"))
			assert.Equal(t, "CODE", r.FormValue("code"))
			assert.Equal(t, "foo-bar-baz", r.FormValue("custom_1"))
			assert.Equal(t, redirectURL.String(), r.FormValue("redirect_uri"))

			idToken, err := jwt.Signed(jwtSigner).Claims(jwt.Claims{
				Issuer:    srv.URL,
				Subject:   "USER_ID",
				Audience:  jwt.Audience{"CLIENT_ID"},
				Expiry:    jwt.NewNumericDate(exp),
				NotBefore: jwt.NewNumericDate(iat),
				IssuedAt:  jwt.NewNumericDate(iat),
				ID:        jti,
			}).CompactSerialize()
			require.NoError(t, err)
			expectedIDToken = idToken

			json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "ACCESS_TOKEN",
				"token_type":    "Bearer",
				"refresh_token": "REFRESH_TOKEN",
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

	customOptionsFn := func(_ context.Context, _ *oauth2.Config) []oauth2.AuthCodeOption {
		return []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("custom_1", "foo-bar-baz")}
	}

	p, err := oidc.New(ctx, &oauth.Options{
		ProviderURL:  srv.URL,
		RedirectURL:  redirectURL,
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
	}, oidc.WithGetExchangeOptions(customOptionsFn))
	require.NoError(t, err)
	require.NotNil(t, p)

	var claims Claims
	oauthToken, err := p.Authenticate(ctx, "CODE", &claims)
	require.NoError(t, err)
	assert.Equal(t, "ACCESS_TOKEN", oauthToken.AccessToken)
	assert.Equal(t, "REFRESH_TOKEN", oauthToken.RefreshToken)
	assert.Equal(t, "Bearer", oauthToken.TokenType)
	assert.Equal(t, Claims{
		"iss":        srv.URL,
		"sub":        "USER_ID",
		"aud":        "CLIENT_ID",
		"exp":        float64(exp.Unix()),
		"nbf":        float64(iat.Unix()),
		"iat":        float64(iat.Unix()),
		"jti":        jti,
		"name":       "John Doe",
		"email":      "john.doe@example.com",
		"RawIDToken": expectedIDToken,
	}, claims)
}

func TestRefresh_WithIDToken(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Second*10)
	t.Cleanup(clearTimeout)

	redirectURL, _ := url.Parse("https://localhost/oauth2/callback")

	jwtSigner, jwks := setupJWTSigning(t)
	iat := time.Now()
	exp := iat.Add(time.Hour)
	jti := uuid.NewString()

	var expectedIDToken string

	// TODO: can this use the mockIDP?

	var srv *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL, err := url.Parse(srv.URL)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer": baseURL.String(),
				"jwks_uri": baseURL.ResolveReference(&url.URL{
					Path: "/jwks",
				}).String(),
				"token_endpoint": baseURL.ResolveReference(&url.URL{
					Path: "/token",
				}).String(),
			})
		case "/jwks":
			json.NewEncoder(w).Encode(jwks)
		case "/token":
			username, password, _ := r.BasicAuth()
			assert.Equal(t, "CLIENT_ID", username)
			assert.Equal(t, "CLIENT_SECRET", password)
			assert.Equal(t, "refresh_token", r.FormValue("grant_type"))
			assert.Equal(t, "EXISTING_REFRESH_TOKEN", r.FormValue("refresh_token"))

			idToken, err := jwt.Signed(jwtSigner).Claims(jwt.Claims{
				Issuer:    srv.URL,
				Subject:   "USER_ID",
				Audience:  jwt.Audience{"CLIENT_ID"},
				Expiry:    jwt.NewNumericDate(exp),
				NotBefore: jwt.NewNumericDate(iat),
				IssuedAt:  jwt.NewNumericDate(iat),
				ID:        jti,
			}).CompactSerialize()
			require.NoError(t, err)
			expectedIDToken = idToken

			json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "ACCESS_TOKEN",
				"token_type":    "Bearer",
				"refresh_token": "NEW_REFRESH_TOKEN", // some providers do rotate refresh tokens
				"expires_in":    3600,
				"id_token":      idToken,
			})
		default:
			assert.Failf(t, "unexpected http request", "url: %s", r.URL.String())
		}
	})
	srv = httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	p, err := oidc.New(ctx, &oauth.Options{
		ProviderURL:  srv.URL,
		RedirectURL:  redirectURL,
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
	})
	require.NoError(t, err)
	require.NotNil(t, p)

	var claims Claims
	existingToken := &oauth2.Token{
		RefreshToken: "EXISTING_REFRESH_TOKEN",
	}
	newToken, err := p.Refresh(ctx, existingToken, &claims)
	require.NoError(t, err)
	assert.Equal(t, "ACCESS_TOKEN", newToken.AccessToken)
	assert.Equal(t, "NEW_REFRESH_TOKEN", newToken.RefreshToken)
	assert.Equal(t, "Bearer", newToken.TokenType)
	assert.Equal(t, Claims{
		"iss":        srv.URL,
		"sub":        "USER_ID",
		"aud":        "CLIENT_ID",
		"exp":        float64(exp.Unix()),
		"nbf":        float64(iat.Unix()),
		"iat":        float64(iat.Unix()),
		"jti":        jti,
		"RawIDToken": expectedIDToken,
	}, claims)
}

func TestRefresh_WithoutIDToken(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Second*10)
	t.Cleanup(clearTimeout)

	redirectURL, _ := url.Parse("https://localhost/oauth2/callback")

	var srv *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL, err := url.Parse(srv.URL)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer": baseURL.String(),
				"token_endpoint": baseURL.ResolveReference(&url.URL{
					Path: "/token",
				}).String(),
			})

		case "/token":
			username, password, _ := r.BasicAuth()
			assert.Equal(t, "CLIENT_ID", username)
			assert.Equal(t, "CLIENT_SECRET", password)
			assert.Equal(t, "refresh_token", r.FormValue("grant_type"))
			assert.Equal(t, "EXISTING_REFRESH_TOKEN", r.FormValue("refresh_token"))

			json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "ACCESS_TOKEN",
				"token_type":    "Bearer",
				"refresh_token": "NEW_REFRESH_TOKEN",
				"expires_in":    3600,
			})
		default:
			assert.Failf(t, "unexpected http request", "url: %s", r.URL.String())
		}
	})
	srv = httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	t.Run("overwrite ID token", func(t *testing.T) {
		p, err := oidc.New(ctx, &oauth.Options{
			ProviderURL:               srv.URL,
			RedirectURL:               redirectURL,
			ClientID:                  "CLIENT_ID",
			ClientSecret:              "CLIENT_SECRET",
			OverwriteIDTokenOnRefresh: true,
		})
		require.NoError(t, err)
		require.NotNil(t, p)

		var claims Claims
		claims.SetRawIDToken("existing-id-token")
		existingToken := &oauth2.Token{
			RefreshToken: "EXISTING_REFRESH_TOKEN",
		}
		newToken, err := p.Refresh(ctx, existingToken, &claims)
		require.NoError(t, err)
		assert.Equal(t, "ACCESS_TOKEN", newToken.AccessToken)
		assert.Equal(t, "NEW_REFRESH_TOKEN", newToken.RefreshToken)
		assert.Equal(t, "Bearer", newToken.TokenType)
		assert.Empty(t, claims)
	})
	t.Run("do not overwrite ID token", func(t *testing.T) {
		p, err := oidc.New(ctx, &oauth.Options{
			ProviderURL:               srv.URL,
			RedirectURL:               redirectURL,
			ClientID:                  "CLIENT_ID",
			ClientSecret:              "CLIENT_SECRET",
			OverwriteIDTokenOnRefresh: false,
		})
		require.NoError(t, err)
		require.NotNil(t, p)

		var claims Claims
		claims.SetRawIDToken("existing-id-token")
		existingToken := &oauth2.Token{
			RefreshToken: "EXISTING_REFRESH_TOKEN",
		}
		newToken, err := p.Refresh(ctx, existingToken, &claims)
		require.NoError(t, err)
		assert.Equal(t, "ACCESS_TOKEN", newToken.AccessToken)
		assert.Equal(t, "NEW_REFRESH_TOKEN", newToken.RefreshToken)
		assert.Equal(t, "Bearer", newToken.TokenType)
		assert.Equal(t, Claims{
			"RawIDToken": "existing-id-token",
		}, claims)
	})
}

func TestRevoke(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Second*10)
	t.Cleanup(clearTimeout)

	var srv *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL, err := url.Parse(srv.URL)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer": baseURL.String(),
				"revocation_endpoint": baseURL.ResolveReference(&url.URL{
					Path: "/revoke",
				}).String(),
			})
		case "/revoke":
			assert.Equal(t, "ACCESS_TOKEN", r.FormValue("token"))
			assert.Equal(t, "access_token", r.FormValue("token_type_hint"))
			assert.Equal(t, "CLIENT_ID", r.FormValue("client_id"))
			assert.Equal(t, "CLIENT_SECRET", r.FormValue("client_secret"))

		default:
			assert.Failf(t, "unexpected http request", "url: %s", r.URL.String())
		}
	})
	srv = httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	redirectURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	p, err := oidc.New(ctx, &oauth.Options{
		ProviderURL:  srv.URL,
		RedirectURL:  redirectURL,
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
	})
	require.NoError(t, err)
	require.NotNil(t, p)

	assert.NoError(t, p.Revoke(ctx, &oauth2.Token{
		AccessToken: "ACCESS_TOKEN",
	}))

	assert.Equal(t, oidc.ErrMissingAccessToken, p.Revoke(ctx, nil))
}

func TestUnsupportedFeatures(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Second*10)
	t.Cleanup(clearTimeout)

	redirectURL, _ := url.Parse("https://localhost/oauth2/callback")

	var srv *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL, err := url.Parse(srv.URL)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer": baseURL.String(),
			})
		default:
			assert.Failf(t, "unexpected http request", "url: %s", r.URL.String())
		}
	})
	srv = httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	p, err := oidc.New(ctx, &oauth.Options{
		ProviderURL:  srv.URL,
		RedirectURL:  redirectURL,
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
	})
	require.NoError(t, err)
	require.NotNil(t, p)

	rec := httptest.NewRecorder()
	err = p.SignOut(rec, httptest.NewRequest(http.MethodGet, "/", nil), "ID_TOKEN", "", "")
	assert.Equal(t, oidc.ErrSignoutNotImplemented, err)

	err = p.Revoke(ctx, &oauth2.Token{
		AccessToken: "ACCESS_TOKEN",
	})
	assert.Equal(t, oidc.ErrRevokeNotImplemented, err)

	_, err = oidc.New(ctx, &oauth.Options{})
	assert.Equal(t, oidc.ErrMissingProviderURL, err)
}

func TestName(t *testing.T) {
	assert.Equal(t, "oidc", (*oidc.Provider)(nil).Name())
}

// setupJWTSigning returns a JWT signer and a corresponding JWKS for signature verification.
func setupJWTSigning(t *testing.T) (jose.Signer, jose.JSONWebKeySet) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwtSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, nil)
	require.NoError(t, err)
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{
			Key:       privateKey.Public(),
			KeyID:     "key",
			Algorithm: "RS256",
			Use:       "sig",
		}},
	}
	return jwtSigner, jwks
}

func TestVerifyAccessToken(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, time.Minute)

	var srv *httptest.Server
	m := http.NewServeMux()
	m.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		baseURL, err := url.Parse(srv.URL)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": baseURL.String(),
			"userinfo_endpoint": baseURL.ResolveReference(&url.URL{
				Path: "/userinfo",
			}).String(),
		})
	})
	m.HandleFunc("GET /userinfo", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer ACCESS_TOKEN", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]any{
			"aud": "AUDIENCE",
			"sub": "SUBJECT",
		})
	})
	srv = httptest.NewServer(m)

	p, err := oidc.New(ctx, &oauth.Options{
		ProviderURL:  srv.URL,
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		RedirectURL:  urlutil.MustParseAndValidateURL("https://www.example.com"),
	})
	require.NoError(t, err)

	claims, err := p.VerifyAccessToken(ctx, "ACCESS_TOKEN")
	require.NoError(t, err)
	assert.Equal(t, map[string]any{
		"aud": "AUDIENCE",
		"sub": "SUBJECT",
	}, claims)
}

func TestVerifyIdentityToken(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, time.Minute)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	jwtSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, nil)
	require.NoError(t, err)
	iat := time.Now().Unix()
	exp := iat + 3600

	var srv *httptest.Server
	m := http.NewServeMux()
	m.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		baseURL, err := url.Parse(srv.URL)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": baseURL.String(),
			"jwks_uri": baseURL.ResolveReference(&url.URL{
				Path: "/jwks",
			}).String(),
		})
	})
	m.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{Key: privateKey.Public(), Use: "sig", Algorithm: "RS256"},
			},
		})
	})
	srv = httptest.NewServer(m)

	rawIdentityToken1, err := jwt.Signed(jwtSigner).Claims(map[string]any{
		"iss": srv.URL,
		"aud": "CLIENT_ID",
		"sub": "subject",
		"exp": exp,
		"iat": iat,
	}).CompactSerialize()
	require.NoError(t, err)

	p, err := oidc.New(ctx, &oauth.Options{
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
