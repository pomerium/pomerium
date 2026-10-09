package oidcbridge

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/oidcbridge/tokens"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func TestConfiguration(t *testing.T) {
	h, err := NewHandlers(nil, nil, exampleConfig())
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	h.HandleOIDCConfiguration(w, r)
	res := w.Result()
	assert.Equal(t, res.StatusCode, http.StatusOK)
	b, _ := io.ReadAll(res.Body)
	assert.JSONEq(t, `{
		"authorization_endpoint": "https://authenticate.example.com/oidc/auth",
		"code_challenge_methods_supported": [
			"S256"
		],
		"end_session_endpoint": "https://authenticate.example.com/.pomerium/sign_out",
		"grant_types_supported": [
			"authorization_code"
		],
		"id_token_signing_alg_values_supported": [
			"RS256"
		],
		"issuer": "https://authenticate.example.com",
		"jwks_uri": "https://authenticate.example.com/oidc/jwks.json",
		"response_types_supported": [
			"code"
		],
		"scopes_supported": [
			"openid"
		],
		"subject_types_supported": [
			"public"
		],
		"token_endpoint": "https://authenticate.example.com/oidc/token",
		"token_endpoint_auth_methods_supported": [
			"client_secret_basic",
			"client_secret_post"
		],
		"userinfo_endpoint": "https://authenticate.example.com/oidc/userinfo"
	}`, string(b))
}

func TestJWKSEndpoint(t *testing.T) {
	// The ID token signing key is derived from the shared secret, so by holding
	// the shared secret fixed here, we can assert on the exact JWKS output.
	fixedSharedSecret := []byte("12345678901234567890123456789012")
	o := exampleConfig()
	o.SharedKey = base64.StdEncoding.EncodeToString(fixedSharedSecret)
	h, err := NewHandlers(nil, nil, o)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/jwks.json", nil)
	h.HandleJWKS(w, r)
	res := w.Result()
	assert.Equal(t, res.StatusCode, http.StatusOK)
	b, _ := io.ReadAll(res.Body)
	assert.JSONEq(t, `{
		"keys": [
			{
				"use": "sig",
				"kty": "RSA",
				"kid": "32ca7c2fc439db3470deaa5f775ef6c7e180023620efeb233abf504509dbc8c6",
				"alg": "RS256",
				"n": "y9J3dmXiFVn1KyoNBA_wA7LrYvLH581ewFkqj7eSebEi1UzYRoxt6xziKkNuxw5ViILshxmQImm6UTaqkA69UBAo_AEU9S71adNjKoLElTu6Gs9U1m0gdHfM7PyrAdE-iDgpcTGX6NCMTjQXXqp66cBER4COjh4SnxN1T9euU9rNC2_gLZ9MB6k-nNzX-8KFzwI5mhhNNF4le50-OxgPiTutI7druQMjRt2OBK3X7yyRqy4xsH0eVNhG1lgwAFq2Bhs0ViIBxEY2iP2K47sATa2CwX9McoG0SXUPHUG9GT1jGtvoh6es_RctFIa64-9YA2WTBLyYWSB4U7j4Cv47SQ",
				"e": "AQAB"
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
	h, err := NewHandlers(nil, nil, exampleConfig())
	require.NoError(t, err)

	t.Run("no client_id", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth", nil)
		h.HandleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		b, _ := io.ReadAll(res.Body)
		assert.Contains(t, string(b), "missing client_id")
	})

	t.Run("no redirect_uri", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth?client_id=foobar", nil)
		h.HandleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		b, _ := io.ReadAll(res.Body)
		assert.Contains(t, string(b), "missing redirect_uri")
	})

	t.Run("invalid redirect_uri", func(t *testing.T) {
		q := url.Values{
			"client_id":    {"https://pkce.example.com"},
			"redirect_uri": {"https://other.example.com/callback"},
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
		h.HandleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		b, _ := io.ReadAll(res.Body)
		assert.Contains(t, string(b), `redirect_uri \"https://other.example.com/callback\" does not match client_id \"https://pkce.example.com\"`)
	})

	t.Run("invalid code_challenge_method", func(t *testing.T) {
		q := url.Values{
			"client_id":             {"https://pkce.example.com"},
			"redirect_uri":          {"https://pkce.example.com/callback"},
			"code_challenge_method": {"plain"},
			"state":                 {"example-state"}, // should be propagated even for an error response
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
		h.HandleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusFound, res.StatusCode)
		require.NoError(t, err)
		assert.Equal(t, "https://pkce.example.com/callback?error=invalid_request&error_description=unsupported+code_challenge_method+%22plain%22&state=example-state", res.Header.Get("Location"))
	})

	t.Run("invalid code_challenge", func(t *testing.T) {
		q := url.Values{
			"client_id":             {"https://pkce.example.com"},
			"redirect_uri":          {"https://pkce.example.com/callback"},
			"code_challenge":        {"foobar"},
			"code_challenge_method": {"S256"},
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
		h.HandleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusFound, res.StatusCode)
		require.NoError(t, err)
		assert.Equal(t, "https://pkce.example.com/callback?error=invalid_request&error_description=invalid+code_challenge", res.Header.Get("Location"))
	})

	t.Run("nonce too large", func(t *testing.T) {
		q := url.Values{
			"client_id":    {"https://non-pkce.example.com"},
			"redirect_uri": {"https://non-pkce.example.com/callback"},
			"nonce":        {strings.Repeat("A", 2000)},
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
		h.HandleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusFound, res.StatusCode)
		require.NoError(t, err)
		assert.Equal(t, "https://non-pkce.example.com/callback?error=invalid_request&error_description=nonce+too+large", res.Header.Get("Location"))
	})

	t.Run("internal error", func(t *testing.T) {
		getSessionHandler := mockGetSessionHandle(nil, errors.New("internal error message"))
		h, err := NewHandlers(getSessionHandler, nil, exampleConfig())
		require.NoError(t, err)

		q := url.Values{
			"client_id":    {"https://non-pkce.example.com"},
			"redirect_uri": {"https://non-pkce.example.com/callback"},
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
		h.HandleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusFound, res.StatusCode)
		require.NoError(t, err)
		assert.Equal(t, "https://non-pkce.example.com/callback?error=server_error&error_description=could+not+retrieve+session", res.Header.Get("Location"))
	})

	t.Run("ok", func(t *testing.T) {
		sh := &session.Handle{
			Id: "session-id",
		}
		getSessionHandler := mockGetSessionHandle(sh, nil)
		h, err := NewHandlers(getSessionHandler, nil, exampleConfig())
		require.NoError(t, err)

		q := url.Values{
			"client_id":             {"https://pkce.example.com"},
			"nonce":                 {"example-nonce"},
			"code_challenge_method": {"S256"},
			"code_challenge":        {"QTytuADJyhDFCbcVU_m4Vkdbpy36C9a-6i0Yo25m0-s"},
			"redirect_uri":          {"https://pkce.example.com/callback"},
			"state":                 {"example-state"},
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
		h.HandleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusFound, res.StatusCode)

		location := res.Header.Get("Location")
		assert.True(t, strings.HasPrefix(location, "https://pkce.example.com/callback"))
		assert.False(t, strings.Contains(location, "error"))

		u, err := url.Parse(res.Header.Get("Location"))
		require.NoError(t, err)
		redirectParams := u.Query()

		// Verify that the state is propagated.
		assert.Equal(t, "example-state", redirectParams.Get("state"))

		// Verify that the code contains the expected encrypted payload.
		code := redirectParams.Get("code")
		p, err := h.codeEncryptor.Decrypt(code, "https://pkce.example.com")
		require.NoError(t, err)
		assert.Equal(t, "https://pkce.example.com/callback", p.RedirectURI)
		assert.True(t, p.Expiration.After(time.Now()), "expiration should be in the future")
		assert.Equal(t, "example-nonce", p.Nonce)
		assert.Equal(t, "QTytuADJyhDFCbcVU_m4Vkdbpy36C9a-6i0Yo25m0-s", p.S256CodeChallenge)
		shBytes, err := base64.StdEncoding.DecodeString(p.SessionToken)
		require.NoError(t, err)
		var sh2 session.Handle
		require.NoError(t, proto.Unmarshal(shBytes, &sh2))
		testutil.AssertProtoEqual(t, sh, &sh2)
	})

	t.Run("client secret", func(t *testing.T) {
		sh := &session.Handle{
			Id: "session-id",
		}
		getSessionHandler := mockGetSessionHandle(sh, nil)
		h, err := NewHandlers(getSessionHandler, nil, exampleConfig())
		require.NoError(t, err)

		q := url.Values{
			"client_id":    {"https://non-pkce.example.com"},
			"redirect_uri": {"https://non-pkce.example.com/callback"},
			"state":        {"abcdef"},
			// no code_challenge or code_challenge_method
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
		h.HandleAuth(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusFound, res.StatusCode)

		location := res.Header.Get("Location")
		assert.True(t, strings.HasPrefix(location, "https://non-pkce.example.com/callback"))

		u, err := url.Parse(res.Header.Get("Location"))
		require.NoError(t, err)
		redirectParams := u.Query()
		assert.Equal(t, "abcdef", redirectParams.Get("state"))
		assert.NotEmpty(t, redirectParams.Get("code"))
	})
}

func TestHandleToken(t *testing.T) {
	h, err := NewHandlers(nil, nil, exampleConfig())
	require.NoError(t, err)

	t.Run("no client_id", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/token", nil)
		h.HandleToken(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{
			"error": "invalid_request",
			"error_description": "missing client_id"
		}`, string(b))
	})

	t.Run("incorrect client_secret", func(t *testing.T) {
		code := h.codeEncryptor.Encrypt(&tokens.CodePayload{
			RedirectURI:  "https://non-pkce.example.com/callback",
			Expiration:   time.Now().Add(5 * time.Minute),
			SessionToken: "foobar",
		}, "https://non-pkce.example.com")
		body := url.Values{
			"client_id":     {"https://non-pkce.example.com"},
			"client_secret": {"BOGUS"},
			"redirect_uri":  {"https://non-pkce.example.com/callback"},
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
		assert.JSONEq(t, `{
			"error": "invalid_request",
			"error_description": "incorrect client_secret"
		}`, string(b))
	})

	t.Run("unsupported grant type", func(t *testing.T) {
		// The 'implicit' grant is not supported.
		body := url.Values{
			"client_id":    {"https://pkce.example.com"},
			"redirect_uri": {"https://pkce.example.com/callback"},
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
		assert.JSONEq(t, `{
			"error": "unsupported_grant_type",
			"error_description": "grant type \"implicit\" is not supported"
		}`, string(b))
	})

	t.Run("invalid code", func(t *testing.T) {
		body := url.Values{
			"client_id":    {"https://pkce.example.com"},
			"redirect_uri": {"https://pkce.example.com/callback"},
			"grant_type":   {"authorization_code"},
			"code":         {"BOGUS"},
		}.Encode()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.HandleToken(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusBadRequest, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{
			"error": "invalid_request",
			"error_description": "invalid authorization code"
		}`, string(b))
	})

	t.Run("code expired", func(t *testing.T) {
		code := h.codeEncryptor.Encrypt(&tokens.CodePayload{
			RedirectURI:  "https://pkce.example.com/callback",
			Expiration:   time.Unix(1791411804, 0),
			SessionToken: "foobar",
		}, "https://pkce.example.com")
		body := url.Values{
			"client_id":    {"https://pkce.example.com"},
			"redirect_uri": {"https://pkce.example.com/callback"},
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
		assert.JSONEq(t, `{
			"error": "invalid_request",
			"error_description": "authorization code expired at 2026-10-07 22:23:24 UTC"
		}`, string(b))
	})

	t.Run("redirect_uri mismatch", func(t *testing.T) {
		code := h.codeEncryptor.Encrypt(&tokens.CodePayload{
			RedirectURI:  "https://example.com/callback",
			Expiration:   time.Now().Add(5 * time.Minute),
			SessionToken: "foobar",
		}, "https://pkce.example.com")
		body := url.Values{
			"client_id":    {"https://pkce.example.com"},
			"redirect_uri": {"https://pkce.example.com/other-callback"},
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
		assert.JSONEq(t, `{
			"error": "invalid_request",
			"error_description": "incorrect or missing redirect_uri"
		}`, string(b))
	})

	t.Run("code_verifier incorrect", func(t *testing.T) {
		code := h.codeEncryptor.Encrypt(&tokens.CodePayload{
			RedirectURI:       "https://pkce.example.com/callback",
			Expiration:        time.Now().Add(5 * time.Minute),
			S256CodeChallenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			SessionToken:      "foobar",
		}, "https://pkce.example.com")
		body := url.Values{
			"client_id":     {"https://pkce.example.com"},
			"redirect_uri":  {"https://pkce.example.com/callback"},
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
		assert.JSONEq(t, `{
			"error": "invalid_request",
			"error_description": "incorrect code_verifier"
		}`, string(b))
	})

	t.Run("session parse error", func(t *testing.T) {
		h, err := NewHandlers(nil, nil, exampleConfig())
		require.NoError(t, err)

		code := h.codeEncryptor.Encrypt(&tokens.CodePayload{
			RedirectURI:  "https://pkce.example.com/callback",
			Expiration:   time.Now().Add(5 * time.Minute),
			SessionToken: "foobar",
		}, "https://pkce.example.com")
		body := url.Values{
			"client_id":    {"https://pkce.example.com"},
			"redirect_uri": {"https://pkce.example.com/callback"},
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

	// Set up a valid session handle.
	sh := &session.Handle{
		Id: "session-id",
	}
	userData := handlers.UserInfoData{
		Session: &session.Session{
			Claims: map[string]*structpb.ListValue{
				"sub": {Values: []*structpb.Value{structpb.NewStringValue("idp-user-id")}},
			},
			ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
		},
	}
	getUserInfoData := func(_ *http.Request, handle *session.Handle) handlers.UserInfoData {
		if proto.Equal(sh, handle) {
			return userData
		}
		return handlers.UserInfoData{}
	}
	h, err = NewHandlers(nil, getUserInfoData, exampleConfig())
	require.NoError(t, err)

	shb, err := proto.Marshal(sh)
	require.NoError(t, err)
	validSessionToken := base64.StdEncoding.EncodeToString(shb)

	// Helper method to verify a successful token response.
	verifyTokenResponse := func(t *testing.T, res *http.Response, expectedAudience string) {
		t.Helper()

		assert.Equal(t, http.StatusOK, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		var result map[string]any
		require.NoError(t, json.Unmarshal(b, &result))
		assert.Nil(t, result["error"])
		assert.GreaterOrEqual(t, result["expires_in"], float64(3000))

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
		assert.Equal(t, "https://authenticate.example.com", idTokenClaims.Issuer)
		assert.Equal(t, jwt.Audience{expectedAudience}, idTokenClaims.Audience)
	}

	t.Run("ok", func(t *testing.T) {
		code := h.codeEncryptor.Encrypt(&tokens.CodePayload{
			RedirectURI:       "https://pkce.example.com/callback",
			S256CodeChallenge: "oluiRWwwc_ynHVbpB3MNDlNq1zV8-vWyT20AsK-_fj4",
			Expiration:        time.Now().Add(5 * time.Minute),
			SessionToken:      validSessionToken,
		}, "https://pkce.example.com")
		body := url.Values{
			"client_id":     {"https://pkce.example.com"},
			"redirect_uri":  {"https://pkce.example.com/callback"},
			"code_verifier": {"example-code-verifier"},
			"grant_type":    {"authorization_code"},
			"code":          {code},
		}.Encode()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.HandleToken(w, r)
		verifyTokenResponse(t, w.Result(), "https://pkce.example.com")
	})

	t.Run("client_secret_basic", func(t *testing.T) {
		code := h.codeEncryptor.Encrypt(&tokens.CodePayload{
			RedirectURI:       "https://non-pkce.example.com/callback",
			S256CodeChallenge: "oluiRWwwc_ynHVbpB3MNDlNq1zV8-vWyT20AsK-_fj4",
			Expiration:        time.Now().Add(5 * time.Minute),
			SessionToken:      validSessionToken,
		}, "https://non-pkce.example.com")
		body := url.Values{
			"redirect_uri":  {"https://non-pkce.example.com/callback"},
			"code_verifier": {"example-code-verifier"},
			"grant_type":    {"authorization_code"},
			"code":          {code},
		}.Encode()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(body))
		r.SetBasicAuth("https%3A%2F%2Fnon-pkce.example.com", "explicit-secret")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.HandleToken(w, r)
		verifyTokenResponse(t, w.Result(), "https://non-pkce.example.com")
	})

	t.Run("client_secret_post", func(t *testing.T) {
		code := h.codeEncryptor.Encrypt(&tokens.CodePayload{
			RedirectURI:       "https://non-pkce.example.com/callback",
			S256CodeChallenge: "oluiRWwwc_ynHVbpB3MNDlNq1zV8-vWyT20AsK-_fj4",
			Expiration:        time.Now().Add(5 * time.Minute),
			SessionToken:      validSessionToken,
		}, "https://non-pkce.example.com")
		body := url.Values{
			"client_id":     {"https://non-pkce.example.com"},
			"client_secret": {"explicit-secret"},
			"redirect_uri":  {"https://non-pkce.example.com/callback"},
			"code_verifier": {"example-code-verifier"},
			"grant_type":    {"authorization_code"},
			"code":          {code},
		}.Encode()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.HandleToken(w, r)
		verifyTokenResponse(t, w.Result(), "https://non-pkce.example.com")
	})
}

func TestHandleUserInfo(t *testing.T) {
	t.Run("no authorization", func(t *testing.T) {
		h, err := NewHandlers(nil, nil, exampleConfig())
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
		h, err := NewHandlers(nil, nil, exampleConfig())
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
		h, err := NewHandlers(nil, nil, exampleConfig())
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
	t.Run("missing session", func(t *testing.T) {
		sh := &session.Handle{
			Id: "session-id",
		}
		getUserInfoData := func(_ *http.Request, handle *session.Handle) handlers.UserInfoData {
			testutil.AssertProtoEqual(t, sh, handle)
			return handlers.UserInfoData{} // no session
		}
		h, err := NewHandlers(nil, getUserInfoData, exampleConfig())
		require.NoError(t, err)

		shb, err := proto.Marshal(sh)
		require.NoError(t, err)
		token := h.accessTokenEncryptor.Encrypt(base64.StdEncoding.EncodeToString(shb))

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		h.HandleUserInfo(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error":"invalid_token"}`, string(b))
	})
	t.Run("expired session", func(t *testing.T) {
		sh := &session.Handle{
			Id: "session-id",
		}
		userData := handlers.UserInfoData{
			Session: &session.Session{
				Claims: map[string]*structpb.ListValue{
					"sub":   {Values: []*structpb.Value{structpb.NewStringValue("idp-user-id")}},
					"email": {Values: []*structpb.Value{structpb.NewStringValue("user@example.com")}},
				},
				ExpiresAt: timestamppb.New(time.Now().Add(-5 * time.Minute)),
			},
		}
		getUserInfoData := func(_ *http.Request, handle *session.Handle) handlers.UserInfoData {
			testutil.AssertProtoEqual(t, sh, handle)
			return userData
		}
		h, err := NewHandlers(nil, getUserInfoData, exampleConfig())
		require.NoError(t, err)

		shb, err := proto.Marshal(sh)
		require.NoError(t, err)
		token := h.accessTokenEncryptor.Encrypt(base64.StdEncoding.EncodeToString(shb))

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		h.HandleUserInfo(w, r)
		res := w.Result()
		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
		b, err := io.ReadAll(res.Body)
		require.NoError(t, err)
		assert.JSONEq(t, `{"error":"invalid_token"}`, string(b))
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
		h, err := NewHandlers(nil, getUserInfoData, exampleConfig())
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

func exampleConfig() *config.Options {
	return &config.Options{
		AuthenticateURLString: "https://authenticate.example.com",
		SharedKey:             base64.StdEncoding.EncodeToString(cryptutil.NewKey()),
		Routes: []config.Policy{
			{
				From:       "https://pkce.example.com",
				To:         config.WeightedURLs{{URL: url.URL{Scheme: "http", Host: "localhost:1234"}}},
				OidcBridge: nullable.From(config.OIDCBridge{}),
			},
			{
				From: "https://non-pkce.example.com",
				To:   config.WeightedURLs{{URL: url.URL{Scheme: "http", Host: "localhost:5678"}}},
				OidcBridge: nullable.From(config.OIDCBridge{
					ClientSecret: nullable.From("explicit-secret"),
				}),
			},
		},
	}
}
