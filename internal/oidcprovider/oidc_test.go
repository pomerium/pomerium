package oidcprovider

import (
	context "context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/authenticate/events"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/oidcprovider/tokens"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/oidc"
)

//go:generate go run go.uber.org/mock/mockgen -write_package_comment=false -package oidcprovider -destination authenticator_mock_test.go github.com/pomerium/pomerium/pkg/identity Authenticator

func TestConfiguration(t *testing.T) {
	h, err := NewHandlers(t.Context(), minimalConfigOptions(), nil)
	require.NoError(t, err)
	router := mux.NewRouter()
	h.Mount(router)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	router.ServeHTTP(w, r)
	res := w.Result()
	assert.Equal(t, res.StatusCode, http.StatusOK)
	b, _ := io.ReadAll(res.Body)
	assert.JSONEq(t, `{
  "authorization_endpoint": "https://example.com/oidc/auth",
  "end_session_endpoint": "https://example.com/.pomerium/sign_out",
  "grant_types_supported": [
    "authorization_code"
  ],
  "id_token_signing_alg_values_supported": [
    "ES256"
  ],
  "issuer": "https://example.com",
  "jwks_uri": "https://example.com/.well-known/jwks.json",
  "request_object_signing_alg_values_supported": [
"EdDSA"
  ],
  "request_parameter_supported": true,
  "response_types_supported": [
    "code"
  ],
  "scopes_supported": [
    "openid"
  ],
  "subject_types_supported": [
    "public"
  ],
  "token_endpoint": "https://example.com/oidc/token",
  "token_endpoint_auth_methods_supported": [
    "private_key_jwt"
  ],
  "userinfo_endpoint": "https://example.com/oidc/userinfo"
}`, string(b))
}

func TestJWKSEndpoint(t *testing.T) {
	// The ID token signing key is derived from the shared secret, so by holding
	// the shared secret fixed here, we can assert on the exact JWKS output.
	fixedSharedSecret := []byte("12345678901234567890123456789012")
	o := minimalConfigOptions()
	o.SharedKey = base64.StdEncoding.EncodeToString(fixedSharedSecret)
	h, err := NewHandlers(t.Context(), o, nil)
	require.NoError(t, err)
	router := mux.NewRouter()
	h.Mount(router)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	router.ServeHTTP(w, r)
	res := w.Result()
	assert.Equal(t, res.StatusCode, http.StatusOK)
	b, _ := io.ReadAll(res.Body)
	assert.JSONEq(t, `{
  "keys": [
    {
      "kid": "a0b236d1cb12aa00db4669be88b716223d515b0b5d6e2deebc46d36b5ab94f33",
      "use": "sig",
      "kty": "EC",
      "crv": "P-256",
      "alg": "ES256",
      "x": "__iIW16-tQ_HrobBWwH6GlJLy0E1MPf1dCdDxTCUsVA",
      "y": "exu-xUFiNI0vA42ZTle1qtqKn6NmEo1n64HC4IHDWho"
    }
  ]
}`, string(b))
}

func TestHandleAuth(t *testing.T) {
	var e authEventRecorder

	h, err := NewHandlers(t.Context(), minimalConfigOptions(), e.fn)
	require.NoError(t, err)

	t.Run("no request object", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth", nil)
		h.handleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("ok", func(t *testing.T) {
		// Mock out the underlying IdP methods.
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockIDP := NewMockAuthenticator(ctrl)
		h.idp = mockIDP

		// Generate a public key pair to identify the client.
		expectedClientKey, key, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		priv := jose.JSONWebKey{Key: key}

		signer, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("jwk", priv.Public()),
		)
		require.NoError(t, err)

		claims := map[string]any{
			"iss":              "https://authenticate.my-domain.example.com",
			"iat":              jwt.NewNumericDate(time.Now()),
			"exp":              jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			"aud":              "https://example.com",
			"client_id":        "https://authenticate.my-domain.example.com",
			"state":            "example-state",
			"pomerium_version": "0.31.0+abcdefg linux/amd64",
		}
		request, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
		require.NoError(t, err)

		var capturedState string
		mockIDP.EXPECT().SignIn(gomock.Any(), gomock.Any(), gomock.Any()).
			Do(func(_ http.ResponseWriter, _ *http.Request, state string) {
				capturedState = state
			})

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth?request="+request, nil)
		r.RemoteAddr = "[2001:0db8::1]:5678"
		h.handleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusOK, res.StatusCode)

		// Verify that the client info was propagated into the 'state' value.
		p, err := h.stateEncryptor.Decrypt(capturedState)
		require.NoError(t, err)
		assert.Equal(t, expectedClientKey, p.ClientKey)
		assert.Equal(t, "https://authenticate.my-domain.example.com", p.ClientID)
		assert.Equal(t, "example-state", p.OriginalState)
		assert.NoError(t, uuid.Validate(p.RequestUUID))

		// Verify that an AuthEvent was logged.
		require.Len(t, e.events, 1)
		assert.Equal(t, events.AuthEvent{
			Event:       events.AuthEventSignInRequest,
			IP:          "2001:0db8::1",
			Version:     "0.31.0+abcdefg linux/amd64",
			RequestUUID: p.RequestUUID,
			PubKey:      base64.RawStdEncoding.EncodeToString(expectedClientKey),
			Domain:      proto.String("authenticate.my-domain.example.com"),
		}, e.events[0])
	})
}

func TestHandleCallback(t *testing.T) {
	h, err := NewHandlers(t.Context(), minimalConfigOptions(), nil)
	require.NoError(t, err)

	t.Run("empty state", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/callback", nil)
		h.handleCallback(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	})

	t.Run("error", func(t *testing.T) {
		clientKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		state := h.stateEncryptor.Encrypt(&tokens.StatePayload{
			ClientID:      "https://client.example.com:1234",
			ClientKey:     clientKey,
			Expiration:    time.Now().Add(5 * time.Minute),
			OriginalState: "example-state",
		})
		callbackURL := "/oidc/callback?" + url.Values{
			"error":             {"invalid_request"},
			"error_description": {"Unsupported response_type value"},
			"state":             {state},
		}.Encode()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, callbackURL, nil)
		h.handleCallback(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusFound, res.StatusCode)
		u, err := url.Parse(res.Header.Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "https", u.Scheme)
		assert.Equal(t, "client.example.com:1234", u.Host)
		assert.Equal(t, url.Values{
			"error":             {"invalid_request"},
			"error_description": {"Unsupported response_type value"},
			"state":             {"example-state"},
		}, u.Query())
	})

	t.Run("ok", func(t *testing.T) {
		clientKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		state := h.stateEncryptor.Encrypt(&tokens.StatePayload{
			ClientID:      "https://client.example.com:1234",
			ClientKey:     clientKey,
			RequestUUID:   "12345678-1234-5678-1234-567812345678",
			Expiration:    time.Now().Add(5 * time.Minute),
			OriginalState: "example-state",
		})
		callbackURL := "/oidc/callback?" + url.Values{
			"state": {state},
			"code":  {"example-code"},
		}.Encode()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, callbackURL, nil)
		r.Header.Set("X-Forwarded-For", "1.2.3.4, 10.1.2.3")
		h.handleCallback(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusFound, res.StatusCode)
		u, err := url.Parse(res.Header.Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "https", u.Scheme)
		assert.Equal(t, "client.example.com:1234", u.Host)
		q := u.Query()
		assert.Equal(t, "example-state", q.Get("state"))

		// Verify the encrypted code payload.
		code := q.Get("code")
		payload, err := h.codeEncryptor.Decrypt(code, "https://client.example.com:1234")
		require.NoError(t, err)
		assert.Equal(t, clientKey, payload.ClientKey)
		assert.Equal(t, "example-code", payload.OriginalCode)
		assert.Equal(t, "1.2.3.4", payload.CallbackIP)
		assert.Equal(t, "12345678-1234-5678-1234-567812345678", payload.RequestUUID)
	})
}

func TestHandleToken_AuthorizationCode(t *testing.T) {
	var e authEventRecorder

	h, err := NewHandlers(t.Context(), minimalConfigOptions(), e.fn)
	require.NoError(t, err)

	t.Run("invalid request", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/token", nil)
		h.handleToken(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error": "invalid_request"}`, string(b))
	})

	// Set up a valid request.

	clientKey, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)
	claims := struct {
		jwt.Claims
		PomeriumVersion string `json:"pomerium_version"`
	}{
		Claims: jwt.Claims{
			Issuer:   "https://client.example.com:1234",
			Audience: jwt.Audience{"https://example.com/oidc/token"},
			Subject:  "https://client.example.com:1234",
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		PomeriumVersion: "0.31.0+abcdefg linux/amd64",
	}
	clientAssertion, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)

	code := h.codeEncryptor.Encrypt(&tokens.CodePayload{
		ClientKey:    clientKey,
		CallbackIP:   "1.2.3.4",
		RequestUUID:  "12345678-1234-5678-1234-567812345678",
		Expiration:   time.Now().Add(5 * time.Minute),
		OriginalCode: "original-code",
	}, "https://client.example.com:1234")

	body := url.Values{
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {clientAssertion},
		"grant_type":            {"authorization_code"},
		"code":                  {code},
	}.Encode()

	t.Run("error", func(t *testing.T) {
		// Mock out the underlying IdP methods.
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockIDP := NewMockAuthenticator(ctrl)
		h.idp = mockIDP

		mockIDP.EXPECT().Authenticate(gomock.Any(), "original-code", gomock.Any()).
			Return(nil, errors.New("upstream oauth error"))

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.handleToken(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error": "server_error"}`, string(b))
	})

	t.Run("ok", func(t *testing.T) {
		// Mock out the underlying IdP methods.
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockIDP := NewMockAuthenticator(ctrl)
		h.idp = mockIDP

		oauthToken := (&oauth2.Token{
			AccessToken:  "example-access-token",
			RefreshToken: "example-refresh-token",
			ExpiresIn:    5555,
		}).WithExtra(map[string]any{
			"id_token": "example-id-token",
		})

		mockIDP.EXPECT().Authenticate(gomock.Any(), "original-code", gomock.Any()).
			DoAndReturn(func(_ context.Context, _ string, out identity.State) (*oauth2.Token, error) {
				_ = identity.Claims{
					"iss":   "https://idp.example.com",
					"aud":   "https://example.com",
					"sub":   "user-id",
					"email": "user@example.com",
				}.Claims(out)
				return oauthToken, nil
			})

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.handleToken(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusOK, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		var result map[string]any
		require.NoError(t, json.Unmarshal(b, &result))
		assert.Equal(t, float64(5555), result["expires_in"])

		// Verify that the access token can be successfully decrypted.
		accessToken, err := h.accessTokenEncryptor.Decrypt(result["access_token"].(string))
		require.NoError(t, err)
		assert.Equal(t, "example-access-token", accessToken)

		// Verify that the refresh token can be successfully decrypted.
		refreshTokenPayload, err := h.refreshTokenEncryptor.Decrypt(
			result["refresh_token"].(string), "https://client.example.com:1234")
		require.NoError(t, err)
		assert.Equal(t, &tokens.RefreshPayload{
			ClientKey: clientKey,
			Token:     "example-refresh-token",
		}, refreshTokenPayload)

		// Verify that the ID token is valid.
		idToken := result["id_token"].(string)
		parsed, err := jwt.ParseSigned(idToken)
		require.NoError(t, err)
		var idTokenClaims jwt.Claims
		require.NoError(t, parsed.Claims(h.publicJWKS, &idTokenClaims))
		assert.Equal(t, "user-id", idTokenClaims.Subject)
		// The issuer and audience should be updated.
		assert.Equal(t, "https://example.com", idTokenClaims.Issuer)
		assert.Equal(t, jwt.Audience{"https://client.example.com:1234"}, idTokenClaims.Audience)

		// Verify that an AuthEvent was logged.
		require.Len(t, e.events, 1)
		assert.Equal(t, events.AuthEvent{
			Event:       events.AuthEventSignInComplete,
			IP:          "1.2.3.4",
			Version:     "0.31.0+abcdefg linux/amd64",
			RequestUUID: "12345678-1234-5678-1234-567812345678",
			PubKey:      base64.RawStdEncoding.EncodeToString(clientKey),
			UID:         proto.String("user-id"),
			Email:       proto.String("user@example.com"),
			Domain:      proto.String("client.example.com"),
		}, e.events[0])
	})

	t.Run("missing subject", func(t *testing.T) {
		// Mock out the underlying IdP methods.
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockIDP := NewMockAuthenticator(ctrl)
		h.idp = mockIDP

		// Do not populate an ID token.
		mockIDP.EXPECT().Authenticate(gomock.Any(), "original-code", gomock.Any()).
			Return(&oauth2.Token{}, nil)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.handleToken(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error": "server_error"}`, string(b))
	})
}

func TestHandleToken_RefreshToken(t *testing.T) {
	h, err := NewHandlers(t.Context(), minimalConfigOptions(), nil)
	require.NoError(t, err)

	// Set up a valid request.

	clientKey, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)
	claims := struct {
		jwt.Claims
		PomeriumVersion string `json:"pomerium_version"`
	}{
		Claims: jwt.Claims{
			Issuer:   "https://client.example.com:1234",
			Audience: jwt.Audience{"https://example.com/oidc/token"},
			Subject:  "https://client.example.com:1234",
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		PomeriumVersion: "0.31.0+abcdefg linux/amd64",
	}
	clientAssertion, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)

	refreshToken := h.refreshTokenEncryptor.Encrypt(&tokens.RefreshPayload{
		ClientKey: clientKey,
		Token:     "idp-refresh-token",
	}, "https://client.example.com:1234")

	body := url.Values{
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {clientAssertion},
		"grant_type":            {"refresh_token"},
		"refresh_token":         {refreshToken},
	}.Encode()

	t.Run("error", func(t *testing.T) {
		// Mock out the underlying IdP methods.
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockIDP := NewMockAuthenticator(ctrl)
		h.idp = mockIDP

		expectedToken := &oauth2.Token{RefreshToken: "idp-refresh-token"}
		mockIDP.EXPECT().Refresh(gomock.Any(), expectedToken, gomock.Any()).
			Return(nil, errors.New("upstream oauth error"))

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.handleToken(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error": "server_error"}`, string(b))
	})

	t.Run("ok", func(t *testing.T) {
		// Mock out the underlying IdP methods.
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockIDP := NewMockAuthenticator(ctrl)
		h.idp = mockIDP

		oauthToken := (&oauth2.Token{
			AccessToken:  "example-access-token",
			RefreshToken: "example-refresh-token",
			ExpiresIn:    5555,
		}).WithExtra(map[string]any{
			"id_token": "example-id-token",
		})

		expectedToken := &oauth2.Token{RefreshToken: "idp-refresh-token"}
		mockIDP.EXPECT().Refresh(gomock.Any(), expectedToken, gomock.Any()).
			DoAndReturn(func(_ context.Context, _ *oauth2.Token, out identity.State) (*oauth2.Token, error) {
				_ = identity.Claims{
					"iss":   "https://idp.example.com",
					"aud":   "https://example.com",
					"sub":   "user-id",
					"email": "user@example.com",
				}.Claims(out)
				return oauthToken, nil
			})

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.handleToken(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusOK, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		var result map[string]any
		require.NoError(t, json.Unmarshal(b, &result))
		assert.Equal(t, float64(5555), result["expires_in"])

		// Verify that the access token can be successfully decrypted.
		accessToken, err := h.accessTokenEncryptor.Decrypt(result["access_token"].(string))
		require.NoError(t, err)
		assert.Equal(t, "example-access-token", accessToken)

		// Verify that the refresh token can be successfully decrypted.
		refreshTokenPayload, err := h.refreshTokenEncryptor.Decrypt(
			result["refresh_token"].(string), "https://client.example.com:1234")
		require.NoError(t, err)
		assert.Equal(t, &tokens.RefreshPayload{
			ClientKey: clientKey,
			Token:     "example-refresh-token",
		}, refreshTokenPayload)

		// Verify that the ID token is valid.
		idToken := result["id_token"].(string)
		parsed, err := jwt.ParseSigned(idToken)
		require.NoError(t, err)
		var idTokenClaims jwt.Claims
		require.NoError(t, parsed.Claims(h.publicJWKS, &idTokenClaims))
		assert.Equal(t, "user-id", idTokenClaims.Subject)
		// The issuer and audience should be updated.
		assert.Equal(t, "https://example.com", idTokenClaims.Issuer)
		assert.Equal(t, jwt.Audience{"https://client.example.com:1234"}, idTokenClaims.Audience)
	})
}

func TestHandleToken_UnsupportedGrantType(t *testing.T) {
	h, err := NewHandlers(t.Context(), minimalConfigOptions(), nil)
	require.NoError(t, err)

	// Set up a valid client assertion.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)
	claims := struct {
		jwt.Claims
		PomeriumVersion string `json:"pomerium_version"`
	}{
		Claims: jwt.Claims{
			Issuer:   "https://client.example.com:1234",
			Audience: jwt.Audience{"https://example.com/oidc/token"},
			Subject:  "https://client.example.com:1234",
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		},
		PomeriumVersion: "0.31.0+abcdefg linux/amd64",
	}
	clientAssertion, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)

	// Request an unsupported grant type.
	body := url.Values{
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {clientAssertion},
		"grant_type":            {"implicit"},
	}.Encode()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.handleToken(w, r)
	res := w.Result()
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	b, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.JSONEq(t, `{"error": "unsupported_grant_type"}`, string(b))
}

func TestHandleUserInfo(t *testing.T) {
	h, err := NewHandlers(t.Context(), minimalConfigOptions(), nil)
	require.NoError(t, err)

	t.Run("no authorization", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
		h.handleUserInfo(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error": "invalid_request"}`, string(b))
	})
	t.Run("invalid authorization format", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
		r.Header.Set("Authorization", "!invalid!")
		h.handleUserInfo(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error": "invalid_request"}`, string(b))
	})
	t.Run("invalid access token", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
		r.Header.Set("Authorization", "Bearer !invalid!")
		h.handleUserInfo(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error": "invalid_token"}`, string(b))
	})

	// Construct a valid token.
	token := h.accessTokenEncryptor.Encrypt("example-access-token")

	t.Run("ok", func(t *testing.T) {
		// Mock out the underlying IdP methods.
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockIDP := NewMockAuthenticator(ctrl)
		h.idp = mockIDP

		var capturedToken *oauth2.Token
		mockIDP.EXPECT().UpdateUserInfo(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, t *oauth2.Token, out any) error {
				capturedToken = t
				_ = identity.Claims{
					"sub":   "user-id",
					"email": "user@example.com",
				}.Claims(out)
				return nil
			})

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		h.handleUserInfo(w, r)
		assert.Equal(t, "example-access-token", capturedToken.AccessToken)
		res := w.Result()
		assert.Equal(t, http.StatusOK, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{
			"sub": "user-id",
			"email": "user@example.com"
		}`, string(b))
	})

	t.Run("idp error", func(t *testing.T) {
		// Mock out the underlying IdP methods.
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		mockIDP := NewMockAuthenticator(ctrl)
		h.idp = mockIDP

		mockIDP.EXPECT().UpdateUserInfo(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, _ *oauth2.Token, _ any) error {
				return errors.New("idp error")
			})

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		h.handleUserInfo(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error": "server_error"}`, string(b))
	})
}

const (
	rsaJWTHeader = `{
  "alg": "RSA",
  "jwk": {
    "kty": "RSA",
    "e": "AQAB",
    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
  }
}`

	mismatchedKeyHeader = `{
  "alg": "EdDSA",
  "jwk": {
    "kty": "RSA",
    "e": "AQAB",
    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
  }
}`

	multipleSignatureJWT = `{
  "protected": "AAAA",
  "payload": "AAAA",
  "signatures": [
    {
      "header": {
        "alg": "RS256",
        "kid": "key1"
      },
      "signature": "signature1"
    },
    {
      "header": {
        "alg": "HS256",
        "kid": "key2"
      },
      "signature": "signature2"
    }
  ]
}`

	privateEd25519Key = `{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "rJuPHXw2W6GFiaOEd_dUdScxVT0b58Ehj_pxS-LrN8E",
  "d": "bOGlMXUodHEcIP6xTI7IhwpDmj_TO9apcIK0AQwXzVY"
}`
	privateKeyHeader = `{
  "alg": "EdDSA",
  "jwk": ` + privateEd25519Key + `
}`

	validHeader = `{
  "alg": "EdDSA",
  "jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "rJuPHXw2W6GFiaOEd_dUdScxVT0b58Ehj_pxS-LrN8E"
  },
  "typ": "JWT"
}`
	validPayload = `{
	"iss": "https://authenticate.my-domain.example.com",
	"iat": 1762893000,
	"exp": 1762893300,
	"aud": "expected audience",
	"client_id": "https://authenticate.my-domain.example.com",
	"state": "expected state"
}`

	invalidClientIDPayload = `{
	"iss": "not-a-url",
	"iat": 1762893000,
	"exp": 1762893300,
	"aud": "expected audience",
	"client_id": "not-a-url",
	"state": "expected state"
}`
)

func TestValidateRequestJWT(t *testing.T) {
	var priv jose.JSONWebKey
	err := json.Unmarshal([]byte(privateEd25519Key), &priv)
	require.NoError(t, err)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("jwk", priv.Public()),
	)
	require.NoError(t, err)

	signJWT := func(t *testing.T, payload string) string {
		t.Helper()
		var parsed map[string]any
		err := json.Unmarshal([]byte(payload), &parsed)
		require.NoError(t, err)
		result, err := jwt.Signed(signer).Claims(parsed).CompactSerialize()
		require.NoError(t, err)
		return result
	}

	now := time.Date(2025, time.November, 11, 20, 32, 0, 0, time.UTC)

	t.Run("missing", func(t *testing.T) {
		_, err := validateAuthRequestJWT("", "expected audience", now)
		assert.ErrorContains(t, err, "no request object provided")
	})
	t.Run("invalid", func(t *testing.T) {
		_, err := validateAuthRequestJWT("not.valid.jwt", "expected audience", now)
		assert.ErrorContains(t, err, "couldn't parse request object")
	})
	t.Run("multiple signatures", func(t *testing.T) {
		// TODO: update to go-jose v4 and use the jwt.ParseCompact method, which
		// should avoid issues related to the full serialization form.
		_, err := validateAuthRequestJWT(multipleSignatureJWT, "expected audience", now)
		assert.ErrorContains(t, err, "expected request object to have one signature, but had 2")
	})
	t.Run("unsupported algorithm", func(t *testing.T) {
		jwt := base64.RawURLEncoding.EncodeToString([]byte(rsaJWTHeader)) + ".payload.signed"
		_, err := validateAuthRequestJWT(jwt, "expected audience", now)
		assert.ErrorContains(t, err, `request object has unsupported signing algorithm "RSA"`)
	})
	t.Run("missing key", func(t *testing.T) {
		jwt := base64.RawURLEncoding.EncodeToString([]byte(`{"alg": "EdDSA"}`)) + ".payload.signed"
		_, err := validateAuthRequestJWT(jwt, "expected audience", now)
		assert.ErrorContains(t, err, `request object header does not have signing key`)
	})
	t.Run("mismatched key type", func(t *testing.T) {
		jwt := base64.RawURLEncoding.EncodeToString([]byte(mismatchedKeyHeader)) + ".payload.signed"
		_, err := validateAuthRequestJWT(jwt, "expected audience", now)
		assert.ErrorContains(t, err, "expected request object signing key to be of type ed25519.PublicKey, found *rsa.PublicKey")
	})
	t.Run("includes private key", func(t *testing.T) {
		jwt := base64.RawURLEncoding.EncodeToString([]byte(privateKeyHeader)) + ".payload.signed"
		_, err := validateAuthRequestJWT(jwt, "expected audience", now)
		assert.ErrorContains(t, err, "invalid embedded jwk, must be public key")
	})
	t.Run("invalid claims", func(t *testing.T) {
		jwt := base64.RawURLEncoding.EncodeToString([]byte(validHeader)) + ".payload.signed"
		_, err := validateAuthRequestJWT(jwt, "expected audience", now)
		assert.ErrorContains(t, err, "couldn't parse request object claims")
	})
	t.Run("valid", func(t *testing.T) {
		jwt := signJWT(t, validPayload)
		req, err := validateAuthRequestJWT(jwt, "expected audience", now)
		assert.NoError(t, err)
		assert.Equal(t, priv.Public().Key, req.Key)
		assert.Equal(t, "https://authenticate.my-domain.example.com", req.ClientID)
		assert.Equal(t, "expected state", req.State)
	})
	t.Run("invalid client ID", func(t *testing.T) {
		jwt := signJWT(t, invalidClientIDPayload)
		_, err := validateAuthRequestJWT(jwt, "expected audience", now)
		assert.ErrorContains(t, err, `invalid request client ID: URL scheme must be "https", got ""`)
	})
	t.Run("unexpected audience", func(t *testing.T) {
		jwt := signJWT(t, validPayload)
		_, err := validateAuthRequestJWT(jwt, "unexpected audience", now)
		assert.ErrorContains(t, err, "request object claims failed validation")
	})
}

func TestValidateClientID(t *testing.T) {
	cases := []struct {
		clientID string
		errorMsg string
	}{
		{"http://example.com", `scheme must be "https", got "http"`},
		{"https://example.com/foo", "must not contain a path"},
		{"https://example.com?bar", "must not contain query parameters"},
		{"https://example.com#baz", "must not contain a fragment"},
		{"https://example\x00.com", "invalid control character"},
	}
	for _, c := range cases {
		t.Run("", func(t *testing.T) {
			assert.ErrorContains(t, validateClientID(c.clientID), c.errorMsg)
		})
	}
}

func TestValidateTokenRequest(t *testing.T) {
	h, err := NewHandlers(t.Context(), minimalConfigOptions(), nil)
	require.NoError(t, err)

	var priv jose.JSONWebKey
	err = json.Unmarshal([]byte(privateEd25519Key), &priv)
	require.NoError(t, err)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)

	// Set a fixed "now" time for comparison against the code expiration and the
	// client assertion expiration.
	now := time.Unix(1762887900, 0)

	t.Run("no client assertion type", func(t *testing.T) {
		q := url.Values{
			"client_assertion": {"fake-jwt"},
		}
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(q.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err := h.validateTokenRequest(r, now)
		assert.ErrorContains(t, err, "private_key_jwt client authentication not present")
	})
	t.Run("no client assertion", func(t *testing.T) {
		q := url.Values{
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		}
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(q.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err := h.validateTokenRequest(r, now)
		assert.ErrorContains(t, err, "private_key_jwt client authentication not present")
	})
	t.Run("invalid client assertion", func(t *testing.T) {
		q := url.Values{
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {"fake-jwt"},
		}
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(q.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err := h.validateTokenRequest(r, now)
		assert.ErrorContains(t, err, "couldn't parse client_assertion")
	})
	t.Run("invalid client assertion subject", func(t *testing.T) {
		q := url.Values{
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			// JWT payload is {"sub": 1234}, which cannot be decoded into a string.
			"client_assertion": {"e30.eyJzdWIiOjEyMzR9.signed"},
		}
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(q.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err := h.validateTokenRequest(r, now)
		assert.ErrorContains(t, err, "invalid client assertion")
	})
	t.Run("invalid authorization code", func(t *testing.T) {
		q := url.Values{
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {"e30.e30.signed"},
			"grant_type":            {"authorization_code"},
			"code":                  {"foo"},
		}
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(q.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err := h.validateTokenRequest(r, now)
		assert.ErrorContains(t, err, "couldn't decrypt authorization code")
	})

	clientKey := priv.Public().Key.(ed25519.PublicKey)
	exampleCode1 := h.codeEncryptor.Encrypt(&tokens.CodePayload{
		ClientKey:    clientKey,
		Expiration:   now.Add(time.Minute),
		OriginalCode: "original-code",
	}, "example-client-id")
	require.NoError(t, err)

	t.Run("invalid client assertion signature", func(t *testing.T) {
		q := url.Values{
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			// JWT payload is {"sub": "example-client-id"} but the signature is bogus.
			"client_assertion": {"e30.eyJzdWIiOiJleGFtcGxlLWNsaWVudC1pZCJ9.signed"},
			"grant_type":       {"authorization_code"},
			"code":             {exampleCode1},
		}
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(q.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err = h.validateTokenRequest(r, time.Unix(1762887900, 0))
		assert.ErrorContains(t, err, "invalid client assertion")
	})

	// Fixture for testing various invalid assertion claims.
	testAssertionClaimsError := func(claims any, errorMsg string) func(t *testing.T) {
		return func(t *testing.T) {
			t.Helper()

			// Generate a client assertion JWT with a valid signature.
			assertion, err := jwt.Signed(signer).Claims(claims).CompactSerialize()
			require.NoError(t, err)

			q := url.Values{
				"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
				"client_assertion":      {assertion},
				"grant_type":            {"authorization_code"},
				"code":                  {exampleCode1},
			}
			r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(q.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			_, err = h.validateTokenRequest(r, now)
			assert.ErrorContains(t, err, errorMsg)
		}
	}
	t.Run("assertion claims type mismatch",
		testAssertionClaimsError((map[string]any{
			"iss": 1234, // type mismatch
			"aud": "https://example.com/oidc/token",
			"sub": "example-client-id",
			"exp": jwt.NewNumericDate(now.Add(time.Minute)),
		}), "invalid client assertion:"))
	t.Run("assertion issuer mismatch",
		testAssertionClaimsError((map[string]any{
			"iss": "not-the-client-id",
			"aud": "https://example.com/oidc/token",
			"sub": "example-client-id",
			"exp": jwt.NewNumericDate(now.Add(time.Minute)),
		}), "invalid issuer claim (iss)"))
	t.Run("assertion audience mismatch",
		testAssertionClaimsError((map[string]any{
			"iss": "example-client-id",
			"aud": "https://other-domain.example.com/oidc/token",
			"sub": "example-client-id",
			"exp": jwt.NewNumericDate(now.Add(time.Minute)),
		}), "invalid audience claim (aud)"))
	t.Run("assertion expired",
		testAssertionClaimsError((map[string]any{
			"iss": "example-client-id",
			"aud": "https://example.com/oidc/token",
			"sub": "example-client-id",
			"exp": jwt.NewNumericDate(now.Add(-time.Hour)),
		}), "token is expired (exp)"))
	t.Run("assertion missing expiry",
		testAssertionClaimsError((map[string]any{
			"iss": "example-client-id",
			"aud": "https://example.com/oidc/token",
			"sub": "example-client-id",
		}), "missing expiry (exp)"))
	t.Run("assertion expiration too late",
		testAssertionClaimsError((map[string]any{
			"iss": "example-client-id",
			"aud": "https://example.com/oidc/token",
			"sub": "example-client-id",
			"exp": jwt.NewNumericDate(now.Add(2 * time.Hour)),
		}), "expiration too far in the future"))

	validClaims := map[string]any{
		"iss": "example-client-id",
		"aud": "https://example.com/oidc/token",
		"sub": "example-client-id",
		"exp": jwt.NewNumericDate(now.Add(5 * time.Minute)),
	}

	t.Run("redirect URI mismatch", func(t *testing.T) {
		assertion, err := jwt.Signed(signer).Claims(validClaims).CompactSerialize()
		require.NoError(t, err)

		q := url.Values{
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {assertion},
			"grant_type":            {"authorization_code"},
			"code":                  {exampleCode1},
			"redirect_uri":          {"not-valid"},
		}
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(q.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err = h.validateTokenRequest(r, now)
		assert.ErrorContains(t, err, "unexpected redirect_uri provided")
	})
	t.Run("redirect URI OK", func(t *testing.T) {
		assertion, err := jwt.Signed(signer).Claims(validClaims).CompactSerialize()
		require.NoError(t, err)

		q := url.Values{
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {assertion},
			"grant_type":            {"authorization_code"},
			"code":                  {exampleCode1},
			"redirect_uri":          {"example-client-id/oauth2/callback"},
		}
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(q.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err = h.validateTokenRequest(r, now)
		assert.NoError(t, err)
	})

	t.Run("valid", func(t *testing.T) {
		assertion, err := jwt.Signed(signer).Claims(validClaims).CompactSerialize()
		require.NoError(t, err)

		q := url.Values{
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {assertion},
			"grant_type":            {"authorization_code"},
			"code":                  {exampleCode1},
		}
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(q.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		data, err := h.validateTokenRequest(r, now)
		assert.NoError(t, err)
		assert.Equal(t, "example-client-id", data.ClientID)
		assert.Equal(t, clientKey, data.ClientKey)
	})

	t.Run("code expired", func(t *testing.T) {
		assertion, err := jwt.Signed(signer).Claims(validClaims).CompactSerialize()
		require.NoError(t, err)

		q := url.Values{
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {assertion},
			"grant_type":            {"authorization_code"},
			"code":                  {exampleCode1},
		}
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(q.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err = h.validateTokenRequest(r, now.Add(2*time.Minute))
		assert.ErrorContains(t, err, "authorization code expired at 2025-11-11 19:06:00 Z")
	})

	t.Run("refresh token invalid", func(t *testing.T) {
		assertion, err := jwt.Signed(signer).Claims(validClaims).CompactSerialize()
		require.NoError(t, err)

		q := url.Values{
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {assertion},
			"grant_type":            {"refresh_token"},
			"refresh_token":         {"foobar"},
		}
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(q.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err = h.validateTokenRequest(r, now)
		assert.ErrorContains(t, err, "couldn't decrypt refresh token")
	})
	t.Run("refresh token ok", func(t *testing.T) {
		refreshToken := h.refreshTokenEncryptor.Encrypt(&tokens.RefreshPayload{
			ClientKey: clientKey,
			Token:     "example-refresh-token",
		}, "example-client-id")

		assertion, err := jwt.Signed(signer).Claims(validClaims).CompactSerialize()
		require.NoError(t, err)

		q := url.Values{
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {assertion},
			"grant_type":            {"refresh_token"},
			"refresh_token":         {refreshToken},
		}
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(q.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		data, err := h.validateTokenRequest(r, now)
		assert.NoError(t, err)
		assert.Equal(t, "example-client-id", data.ClientID)
		assert.Equal(t, clientKey, data.ClientKey)
	})

	t.Run("unsupported grant type", func(t *testing.T) {
		assertion, err := jwt.Signed(signer).Claims(validClaims).CompactSerialize()
		require.NoError(t, err)

		q := url.Values{
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {assertion},
			"grant_type":            {"implicit"},
		}
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(q.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		_, err = h.validateTokenRequest(r, now)
		assert.ErrorContains(t, err, `unsupported grant type requested: "implicit"`)
		if assert.IsType(t, &errorCodeError{}, err) {
			assert.Equal(t, "unsupported_grant_type", err.(*errorCodeError).errorCode) //nolint:errorlint
		}
	})
}

func minimalConfigOptions() *config.Options {
	return &config.Options{
		AuthenticateURLString: "https://example.com",
		SharedKey:             base64.StdEncoding.EncodeToString(cryptutil.NewKey()),
		Provider:              oidc.Name,
		ProviderURL:           "https://unused.example.com",
	}
}

type authEventRecorder struct {
	events []events.AuthEvent
}

func (r *authEventRecorder) fn(_ context.Context, evt events.AuthEvent) {
	r.events = append(r.events, evt)
}
