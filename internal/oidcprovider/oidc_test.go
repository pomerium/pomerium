package oidcprovider

import (
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

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/oidcprovider/tokens"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConfiguration(t *testing.T) {
	h, err := NewHandlers(t.Context(), nil, nil, minimalConfigOptions())
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	h.HandleOIDCConfiguration(w, r)
	res := w.Result()
	assert.Equal(t, res.StatusCode, http.StatusOK)
	b, _ := io.ReadAll(res.Body)
	assert.JSONEq(t, `{
		"authorization_endpoint": "https://example.com/oidc/auth",
		"code_challenge_methods_supported": [
			"S256"
		],
		"end_session_endpoint": "https://example.com/.pomerium/sign_out",
		"grant_types_supported": [
			"authorization_code"
		],
		"id_token_signing_alg_values_supported": [
			"ES256"
		],
		"issuer": "https://example.com",
		"jwks_uri": "https://example.com/.well-known/jwks.json",
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
			"client_secret_post"
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
	h, err := NewHandlers(t.Context(), nil, nil, o)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	h.HandleJWKS(w, r)
	res := w.Result()
	assert.Equal(t, res.StatusCode, http.StatusOK)
	b, _ := io.ReadAll(res.Body)
	assert.JSONEq(t, `{
		"keys": [
			{
				"kid": "8c5d6801c2ae2082d3fd6b273b57294f5565215ba7ad044c8ab8e1d2c7c8a646",
				"use": "sig",
				"kty": "EC",
				"crv": "P-256",
				"alg": "ES256",
				"x": "NSpuY82_9pY6EaKk3rBovIZkY8AjPOoKRR1NFxlMRm0",
				"y": "rOr78DfOGIgF478nH8yo-I5PIn8JcY9nUx5GFknhcBs"
			}
		]
	}`, string(b))
}

func mockGetSessionHandle(sh *session.Handle, err error) func(*http.Request) (*session.Handle, error) {
	return func(*http.Request) (*session.Handle, error) {
		return sh, err
	}
}

func TestHandleAuth(t *testing.T) {
	t.Run("no client_id", func(t *testing.T) {
		h, err := NewHandlers(t.Context(), nil, nil, minimalConfigOptions())
		require.NoError(t, err)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth", nil)
		h.HandleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		b, _ := io.ReadAll(res.Body)
		assert.Contains(t, string(b), "client_id is required")
	})

	t.Run("no redirect_uri", func(t *testing.T) {
		h, err := NewHandlers(t.Context(), nil, nil, minimalConfigOptions())
		require.NoError(t, err)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth?client_id=foobar", nil)
		h.HandleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		b, _ := io.ReadAll(res.Body)
		assert.Contains(t, string(b), "redirect_uri is required")
	})

	t.Run("invalid redirect_uri", func(t *testing.T) {
		h, err := NewHandlers(t.Context(), nil, nil, minimalConfigOptions())
		require.NoError(t, err)

		q := url.Values{
			"client_id":    {"https://example.com"},
			"redirect_uri": {"https://other.example.com/callback"},
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
		h.HandleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		b, _ := io.ReadAll(res.Body)
		assert.Contains(t, string(b), `invalid redirect_uri: redirect_uri \"https://other.example.com/callback\" does not match client_id \"https://example.com\"`)
	})

	t.Run("invalid code_challenge_method", func(t *testing.T) {
		h, err := NewHandlers(t.Context(), nil, nil, minimalConfigOptions())
		require.NoError(t, err)

		q := url.Values{
			"client_id":             {"https://example.com"},
			"redirect_uri":          {"https://example.com/callback"},
			"code_challenge_method": {"plain"},
			"state":                 {"example-state"}, // should be propagated even for an error response
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
		h.HandleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusFound, res.StatusCode)
		require.NoError(t, err)
		assert.Equal(t, "https://example.com/callback?error=invalid_request&error_description=unsupported+code_challenge_method+%22plain%22&state=example-state", res.Header.Get("Location"))
	})

	t.Run("invalid code_challenge", func(t *testing.T) {
		h, err := NewHandlers(t.Context(), nil, nil, minimalConfigOptions())
		require.NoError(t, err)

		q := url.Values{
			"client_id":             {"https://example.com"},
			"redirect_uri":          {"https://example.com/callback"},
			"code_challenge":        {"foobar"},
			"code_challenge_method": {"S256"},
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
		h.HandleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusFound, res.StatusCode)
		require.NoError(t, err)
		assert.Equal(t, "https://example.com/callback?error=invalid_request&error_description=invalid+code_challenge", res.Header.Get("Location"))
	})

	t.Run("nonce too large", func(t *testing.T) {
		h, err := NewHandlers(t.Context(), nil, nil, minimalConfigOptions())
		require.NoError(t, err)

		q := url.Values{
			"client_id":    {"https://example.com"},
			"redirect_uri": {"https://example.com/callback"},
			"nonce":        {strings.Repeat("A", 2000)},
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
		h.HandleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusFound, res.StatusCode)
		require.NoError(t, err)
		assert.Equal(t, "https://example.com/callback?error=invalid_request&error_description=nonce+too+large", res.Header.Get("Location"))
	})

	t.Run("internal error", func(t *testing.T) {
		getSessionHandler := mockGetSessionHandle(nil, errors.New("internal error message"))
		h, err := NewHandlers(t.Context(), getSessionHandler, nil, minimalConfigOptions())
		require.NoError(t, err)

		q := url.Values{
			"client_id":    {"https://example.com"},
			"redirect_uri": {"https://example.com/callback"},
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
		h.HandleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusFound, res.StatusCode)
		require.NoError(t, err)
		assert.Equal(t, "https://example.com/callback?error=server_error&error_description=could+not+retrieve+session", res.Header.Get("Location"))
	})

	t.Run("ok", func(t *testing.T) {
		sh := &session.Handle{
			Id: "session-id",
		}
		getSessionHandler := mockGetSessionHandle(sh, nil)
		h, err := NewHandlers(t.Context(), getSessionHandler, nil, minimalConfigOptions())
		require.NoError(t, err)

		q := url.Values{
			"client_id":             {"https://example.com"},
			"nonce":                 {"example-nonce"},
			"code_challenge_method": {"S256"},
			"code_challenge":        {"QTytuADJyhDFCbcVU_m4Vkdbpy36C9a-6i0Yo25m0-s="},
			"redirect_uri":          {"https://example.com/callback"},
			"state":                 {"example-state"},
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
		h.HandleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusFound, res.StatusCode)

		location := res.Header.Get("Location")
		assert.True(t, strings.HasPrefix(location, "https://example.com/callback"))

		u, err := url.Parse(res.Header.Get("Location"))
		require.NoError(t, err)
		redirectParams := u.Query()

		// Verify that the state is propagated.
		assert.Equal(t, "example-state", redirectParams.Get("state"))

		// Verify that the code contains the expected encrypted payload.
		code := redirectParams.Get("code")
		p, err := h.codeEncryptor.Decrypt(code, "https://example.com")
		require.NoError(t, err)
		assert.Equal(t, "https://example.com/callback", p.RedirectURI)
		assert.True(t, p.Expiration.After(time.Now()), "expiration should be in the future")
		assert.Equal(t, "example-nonce", p.Nonce)
		assert.Equal(t, "QTytuADJyhDFCbcVU_m4Vkdbpy36C9a-6i0Yo25m0-s=", p.S256CodeChallenge)
		shBytes, err := base64.StdEncoding.DecodeString(p.SessionToken)
		require.NoError(t, err)
		var sh2 session.Handle
		require.NoError(t, proto.Unmarshal(shBytes, &sh2))
		testutil.AssertProtoEqual(t, sh, &sh2)
	})

	t.Run("challenge not required", func(t *testing.T) {
		sh := &session.Handle{
			Id: "session-id",
		}
		getSessionHandler := mockGetSessionHandle(sh, nil)
		h, err := NewHandlers(t.Context(), getSessionHandler, nil, minimalConfigOptions())
		require.NoError(t, err)

		q := url.Values{
			"client_id":    {"https://example.com"},
			"redirect_uri": {"https://example.com/callback"},
			"state":        {"abcdef"},
			// no code_challenge or code_challenge_method
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
		h.HandleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusFound, res.StatusCode)

		location := res.Header.Get("Location")
		assert.True(t, strings.HasPrefix(location, "https://example.com/callback"))

		u, err := url.Parse(res.Header.Get("Location"))
		require.NoError(t, err)
		redirectParams := u.Query()
		assert.Equal(t, "abcdef", redirectParams.Get("state"))
		assert.NotEmpty(t, redirectParams.Get("code"))
	})
}

func TestHandleToken(t *testing.T) {
	t.Run("no client_id", func(t *testing.T) {
		h, err := NewHandlers(t.Context(), nil, nil, minimalConfigOptions())
		require.NoError(t, err)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/token", nil)
		h.HandleToken(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error": "invalid_client"}`, string(b))
	})

	t.Run("unsupported grant type", func(t *testing.T) {
		h, err := NewHandlers(t.Context(), nil, nil, minimalConfigOptions())
		require.NoError(t, err)

		// The 'implicit' grant is not supported.
		body := url.Values{
			"client_id":    {"https://example.com"},
			"redirect_uri": {"https://example.com/callback"},
			"grant_type":   {"implicit"},
		}.Encode()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.HandleToken(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error": "unsupported_grant_type"}`, string(b))
	})

	t.Run("code expired", func(t *testing.T) {
		h, err := NewHandlers(t.Context(), nil, nil, minimalConfigOptions())
		require.NoError(t, err)

		code := h.codeEncryptor.Encrypt(&tokens.CodePayload{
			RedirectURI:  "https://example.com/callback",
			Expiration:   time.Now().Add(-5 * time.Minute),
			SessionToken: "foobar",
		}, "https://example.com")
		body := url.Values{
			"client_id":    {"https://example.com"},
			"redirect_uri": {"https://example.com/callback"},
			"grant_type":   {"authorization_code"},
			"code":         {code},
		}.Encode()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.HandleToken(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error": "invalid_request"}`, string(b))
	})

	t.Run("redirect_uri mismatch", func(t *testing.T) {
		h, err := NewHandlers(t.Context(), nil, nil, minimalConfigOptions())
		require.NoError(t, err)

		code := h.codeEncryptor.Encrypt(&tokens.CodePayload{
			RedirectURI:  "https://example.com/callback",
			Expiration:   time.Now().Add(5 * time.Minute),
			SessionToken: "foobar",
		}, "https://example.com")
		body := url.Values{
			"client_id":    {"https://example.com"},
			"redirect_uri": {"https://example.com/other-callback"},
			"grant_type":   {"authorization_code"},
			"code":         {code},
		}.Encode()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.HandleToken(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error": "invalid_request"}`, string(b))
	})

	t.Run("code_verifier incorrect", func(t *testing.T) {
		h, err := NewHandlers(t.Context(), nil, nil, minimalConfigOptions())
		require.NoError(t, err)

		code := h.codeEncryptor.Encrypt(&tokens.CodePayload{
			RedirectURI:       "https://example.com/callback",
			Expiration:        time.Now().Add(5 * time.Minute),
			S256CodeChallenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			SessionToken:      "foobar",
		}, "https://example.com")
		body := url.Values{
			"client_id":     {"https://example.com"},
			"redirect_uri":  {"https://example.com/callback"},
			"code_verifier": {"example-code-verifier"},
			"grant_type":    {"authorization_code"},
			"code":          {code},
		}.Encode()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.HandleToken(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error": "invalid_request"}`, string(b))
	})

	t.Run("session parse error", func(t *testing.T) {
		h, err := NewHandlers(t.Context(), nil, nil, minimalConfigOptions())
		require.NoError(t, err)

		code := h.codeEncryptor.Encrypt(&tokens.CodePayload{
			RedirectURI:  "https://example.com/callback",
			Expiration:   time.Now().Add(5 * time.Minute),
			SessionToken: "foobar",
		}, "https://example.com")
		body := url.Values{
			"client_id":    {"https://example.com"},
			"redirect_uri": {"https://example.com/callback"},
			"grant_type":   {"authorization_code"},
			"code":         {code},
		}.Encode()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.HandleToken(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusInternalServerError, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error": "server_error"}`, string(b))
	})

	t.Run("ok", func(t *testing.T) {
		sh := &session.Handle{
			Id: "session-id",
		}
		userData := handlers.UserInfoData{
			Session: &session.Session{
				Claims: map[string]*structpb.ListValue{
					"sub": {Values: []*structpb.Value{structpb.NewStringValue("idp-user-id")}},
				},
			},
		}
		getUserInfoData := func(_ *http.Request, handle *session.Handle) handlers.UserInfoData {
			testutil.AssertProtoEqual(t, sh, handle)
			return userData
		}

		h, err := NewHandlers(t.Context(), nil, getUserInfoData, minimalConfigOptions())
		require.NoError(t, err)

		shb, err := proto.Marshal(sh)
		require.NoError(t, err)
		st := base64.StdEncoding.EncodeToString(shb)

		code := h.codeEncryptor.Encrypt(&tokens.CodePayload{
			RedirectURI:       "https://client.example.com/callback",
			S256CodeChallenge: "oluiRWwwc_ynHVbpB3MNDlNq1zV8-vWyT20AsK-_fj4=",
			Expiration:        time.Now().Add(5 * time.Minute),
			SessionToken:      st,
		}, "https://client.example.com")
		body := url.Values{
			"client_id":     {"https://client.example.com"},
			"redirect_uri":  {"https://client.example.com/callback"},
			"code_verifier": {"example-code-verifier"},
			"grant_type":    {"authorization_code"},
			"code":          {code},
		}.Encode()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.HandleToken(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusOK, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		var result map[string]any
		require.NoError(t, json.Unmarshal(b, &result))
		assert.GreaterOrEqual(t, float64(5555), result["expires_in"])

		// Verify that the access token can be successfully decrypted.
		accessTokenString, ok := result["access_token"].(string)
		require.True(t, ok, "expected an access_token string")
		accessToken, err := h.accessTokenEncryptor.Decrypt(accessTokenString)
		require.NoError(t, err)
		assert.Equal(t, "CgpzZXNzaW9uLWlk", accessToken)

		// Verify that the ID token is valid.
		idToken, ok := result["id_token"].(string)
		require.True(t, ok, "expected an id_token string")
		parsed, err := jwt.ParseSigned(idToken)
		require.NoError(t, err)
		var idTokenClaims jwt.Claims
		require.NoError(t, parsed.Claims(h.publicJWKS, &idTokenClaims))
		assert.Equal(t, "idp-user-id", idTokenClaims.Subject)
		// The issuer and audience should be updated.
		assert.Equal(t, "https://example.com", idTokenClaims.Issuer)
		assert.Equal(t, jwt.Audience{"https://client.example.com"}, idTokenClaims.Audience)
	})
}

func TestHandleUserInfo(t *testing.T) {
	t.Run("no authorization", func(t *testing.T) {
		h, err := NewHandlers(t.Context(), nil, nil, minimalConfigOptions())
		require.NoError(t, err)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
		h.HandleUserInfo(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error": "invalid_request"}`, string(b))
	})
	t.Run("invalid authorization format", func(t *testing.T) {
		h, err := NewHandlers(t.Context(), nil, nil, minimalConfigOptions())
		require.NoError(t, err)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
		r.Header.Set("Authorization", "!invalid!")
		h.HandleUserInfo(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error": "invalid_request"}`, string(b))
	})
	t.Run("invalid access token", func(t *testing.T) {
		h, err := NewHandlers(t.Context(), nil, nil, minimalConfigOptions())
		require.NoError(t, err)

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
		r.Header.Set("Authorization", "Bearer !invalid!")
		h.HandleUserInfo(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error": "invalid_token"}`, string(b))
	})

	t.Run("ok", func(t *testing.T) {
		sh := &session.Handle{
			Id: "session-id",
		}
		userData := handlers.UserInfoData{
			Session: &session.Session{
				Claims: map[string]*structpb.ListValue{
					"sub":   {Values: []*structpb.Value{structpb.NewStringValue("idp-user-id")}},
					"email": {Values: []*structpb.Value{structpb.NewStringValue("user@example.com")}},
				},
			},
		}
		getUserInfoData := func(_ *http.Request, handle *session.Handle) handlers.UserInfoData {
			testutil.AssertProtoEqual(t, sh, handle)
			return userData
		}
		h, err := NewHandlers(t.Context(), nil, getUserInfoData, minimalConfigOptions())
		require.NoError(t, err)

		shb, err := proto.Marshal(sh)
		require.NoError(t, err)
		token := h.accessTokenEncryptor.Encrypt(base64.StdEncoding.EncodeToString(shb))

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		h.HandleUserInfo(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusOK, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{
			"sub": "idp-user-id",
			"email": "user@example.com"
		}`, string(b))
	})
}

func TestValidateClientIDAndRedirectURI(t *testing.T) {
	okCases := []struct {
		clientID    string
		redirectURI string
	}{
		{"https://example.com", "https://example.com/callback"},
		{"https://example.com", "https://example.com"},
	}
	for _, c := range okCases {
		t.Run("ok", func(t *testing.T) {
			err := validateClientIDAndRedirectURI(c.clientID, c.redirectURI)
			assert.NoError(t, err)
		})
	}
	errorCases := []struct {
		clientID    string
		redirectURI string
		errorMsg    string
	}{
		{"http://example.com", "", `URL scheme must be "https", got "http"`},
		{"https://example.com?bar", "", "URL must not contain query parameters"},
		{"https://example.com#baz", "", "URL must not contain a fragment"},
		{"https://example\x00.com", "", "invalid control character"},
		{"https://example.com", "https://other.example.com/callback", "does not match client_id"},
	}
	for _, c := range errorCases {
		t.Run("error", func(t *testing.T) {
			err := validateClientIDAndRedirectURI(c.clientID, c.redirectURI)
			assert.ErrorContains(t, err, c.errorMsg)
		})
	}
}

func minimalConfigOptions() *config.Options {
	return &config.Options{
		AuthenticateURLString: "https://example.com",
		SharedKey:             base64.StdEncoding.EncodeToString(cryptutil.NewKey()),
		Provider:              oidc.Name,
		ProviderURL:           "https://unused.example.com",
	}
}
