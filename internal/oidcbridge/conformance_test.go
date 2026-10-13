package oidcbridge

// Regression tests for defects found by running the OpenID Foundation
// conformance suite (OIDC Basic OP plan) against the bridge; see
// internal/acceptance/suites/oidc-conformance. Each test is named after the
// conformance module that found the defect.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/oidcbridge/tokens"
	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

const (
	conformanceClientID    = "https://non-pkce.example.com"
	conformanceRedirectURI = "https://non-pkce.example.com"
	conformanceSecret      = "explicit-secret"
)

// conformanceFixture is a bridge with one confidential client, an in-memory
// databroker, and one user who signed in a minute ago.
type conformanceFixture struct {
	h        *Handlers
	sessions *fakeSessions
}

func newConformanceFixture(t *testing.T) *conformanceFixture {
	t.Helper()
	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, srv)
	})

	sh := &session.Handle{Id: "session-id"}
	data := handlers.UserInfoData{Session: &session.Session{
		Claims: map[string]*structpb.ListValue{
			"sub": {Values: []*structpb.Value{structpb.NewStringValue("idp-user-id")}},
		},
		IssuedAt:  timestamppb.New(time.Now().Add(-time.Minute)),
		ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
	}}
	h, err := NewHandlers(func(_ *http.Request, handle *session.Handle) handlers.UserInfoData {
		if proto.Equal(sh, handle) {
			return data
		}
		return handlers.UserInfoData{}
	}, databrokerpb.NewDataBrokerServiceClient(cc), exampleConfig())
	require.NoError(t, err)
	return &conformanceFixture{h: h, sessions: &fakeSessions{handle: sh}}
}

func conformanceAuthParams(extra ...string) url.Values {
	q := url.Values{
		"client_id":     {conformanceClientID},
		"redirect_uri":  {conformanceRedirectURI},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"example-state"},
		"nonce":         {"example-nonce"},
	}
	for i := 0; i+1 < len(extra); i += 2 {
		if extra[i+1] == "" {
			q.Del(extra[i])
		} else {
			q.Set(extra[i], extra[i+1])
		}
	}
	return q
}

func (f *conformanceFixture) authorize(t *testing.T, q url.Values) *http.Response {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
	f.h.HandleAuth(w, r, f.sessions)
	return w.Result()
}

// callbackParams asserts that the response redirects to the client's
// redirect_uri and returns the callback parameters.
func callbackParams(t *testing.T, res *http.Response) url.Values {
	t.Helper()
	require.Equal(t, http.StatusFound, res.StatusCode)
	u, err := url.Parse(res.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, conformanceRedirectURI, (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}).String(),
		"expected a redirect to the client, got %s", u)
	return u.Query()
}

// exchangeCode exchanges code at the token endpoint as the conformance client,
// authenticating with secret.
func exchangeCode(t *testing.T, h *Handlers, code, secret string) (*http.Response, map[string]any) {
	t.Helper()
	body := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {conformanceRedirectURI},
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(body.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(url.QueryEscape(conformanceClientID), secret)
	h.HandleToken(w, r)
	res := w.Result()
	var result map[string]any
	require.NoError(t, json.NewDecoder(res.Body).Decode(&result))
	return res, result
}

func (f *conformanceFixture) redeem(t *testing.T, code string) (*http.Response, map[string]any) {
	t.Helper()
	return exchangeCode(t, f.h, code, conformanceSecret)
}

func (f *conformanceFixture) userInfo(t *testing.T, accessToken string) *http.Response {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+accessToken)
	f.h.HandleUserInfo(w, r)
	return w.Result()
}

// idTokenClaims verifies the ID token in a token response and returns its
// claims.
func idTokenClaims(t *testing.T, h *Handlers, tokenResponse map[string]any) map[string]any {
	t.Helper()
	parsed, err := jwt.ParseSigned(tokenResponse["id_token"].(string))
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, parsed.Claims(h.publicJWKS, &claims))
	return claims
}

// oidcc-response-type-missing: an authorization request without a
// response_type was answered with a code.
func TestConformance_ResponseTypeMissing(t *testing.T) {
	f := newConformanceFixture(t)

	params := callbackParams(t, f.authorize(t, conformanceAuthParams("response_type", "")))
	assert.Equal(t, "invalid_request", params.Get("error"))
	assert.Equal(t, "example-state", params.Get("state"))
	assert.Empty(t, params.Get("code"))

	params = callbackParams(t, f.authorize(t, conformanceAuthParams("response_type", "token")))
	assert.Equal(t, "unsupported_response_type", params.Get("error"))
	assert.Empty(t, params.Get("code"))
}

// oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported:
// a request object was silently ignored, so its state and nonce were lost. An
// OP that does not support request objects must say so.
func TestConformance_RequestObjectRejectedAsUnsupported(t *testing.T) {
	f := newConformanceFixture(t)

	params := callbackParams(t, f.authorize(t, conformanceAuthParams("request", "eyJhbGciOiJub25lIn0.e30.")))
	assert.Equal(t, "request_not_supported", params.Get("error"))
	assert.Empty(t, params.Get("code"))

	params = callbackParams(t, f.authorize(t, conformanceAuthParams("request_uri", "https://client.example.com/request.jwt")))
	assert.Equal(t, "request_uri_not_supported", params.Get("error"))
	assert.Empty(t, params.Get("code"))

	// Discovery must say so too (request_uri_parameter_supported defaults to
	// true); TestConfiguration covers that.
}

// oidcc-ensure-registered-redirect-uri and
// oidcc-ensure-request-object-with-redirect-uri: a redirect_uri below the
// client_id URL was accepted and sent a code to a URI that was never
// registered. Redirect URIs must match exactly (OIDC Core 3.1.2.1, RFC 9700
// 4.1.3), so an error page is shown instead of redirecting.
func TestConformance_EnsureRegisteredRedirectURI(t *testing.T) {
	f := newConformanceFixture(t)

	for _, redirectURI := range []string{
		conformanceRedirectURI + "/callback",
		conformanceRedirectURI + "/callback/xp5CHohSJI",
	} {
		res := f.authorize(t, conformanceAuthParams("redirect_uri", redirectURI))
		assert.Equal(t, http.StatusBadRequest, res.StatusCode, redirectURI)
		assert.Empty(t, res.Header.Get("Location"), redirectURI)
	}
}

// oidcc-prompt-none-not-logged-in: with prompt=none and no session, the user
// was sent to the identity provider's login page instead of the client
// getting login_required.
func TestConformance_PromptNoneNotLoggedIn(t *testing.T) {
	f := newConformanceFixture(t)
	f.sessions = &fakeSessions{err: errors.New("no session")}

	params := callbackParams(t, f.authorize(t, conformanceAuthParams("prompt", "none")))
	assert.Equal(t, "login_required", params.Get("error"))
	assert.Equal(t, "example-state", params.Get("state"))
	assert.Nil(t, f.sessions.reauthURL)
}

// oidcc-prompt-login: prompt=login neither re-authenticated the user nor
// returned an error. The user must sign in again at the identity provider,
// and then the original request continues (without asking yet again).
func TestConformance_PromptLogin(t *testing.T) {
	f := newConformanceFixture(t)

	res := f.authorize(t, conformanceAuthParams("prompt", "login"))
	assert.Equal(t, http.StatusFound, res.StatusCode)
	require.NotNil(t, f.sessions.reauthURL, "expected the user to be sent to sign in again")
	assert.Equal(t, "login", f.sessions.reauthParams.Get("prompt"))
	assert.Equal(t, conformanceAuthParams(), f.sessions.reauthURL.Query())
}

// oidcc-max-age-1 and oidcc-max-age-10000: max_age was ignored and the ID
// token had no auth_time.
func TestConformance_MaxAge(t *testing.T) {
	t.Run("session too old", func(t *testing.T) {
		f := newConformanceFixture(t)
		res := f.authorize(t, conformanceAuthParams("max_age", "1"))
		assert.Equal(t, http.StatusFound, res.StatusCode)
		require.NotNil(t, f.sessions.reauthURL, "expected the user to be sent to sign in again")
		assert.Equal(t, "1", f.sessions.reauthParams.Get("max_age"))
		assert.Equal(t, conformanceAuthParams(), f.sessions.reauthURL.Query())
	})
	t.Run("session recent enough", func(t *testing.T) {
		f := newConformanceFixture(t)
		params := callbackParams(t, f.authorize(t, conformanceAuthParams("max_age", "10000")))
		require.NotEmpty(t, params.Get("code"), params.Get("error_description"))
		assert.Nil(t, f.sessions.reauthURL)

		res, tokenResponse := f.redeem(t, params.Get("code"))
		require.Equal(t, http.StatusOK, res.StatusCode, tokenResponse)
		claims := idTokenClaims(t, f.h, tokenResponse)
		require.Contains(t, claims, "auth_time")
		assert.InDelta(t, time.Now().Add(-time.Minute).Unix(), claims["auth_time"], 5)
	})
	t.Run("invalid", func(t *testing.T) {
		f := newConformanceFixture(t)
		params := callbackParams(t, f.authorize(t, conformanceAuthParams("max_age", "-1")))
		assert.Equal(t, "invalid_request", params.Get("error"))
	})
}

// oidcc-ensure-post-request-succeeds: the authorization endpoint must accept
// POST (OIDC Core 3.1.2.1), including when the user has to sign in first.
func TestConformance_EnsurePostRequestSucceeds(t *testing.T) {
	post := func(f *conformanceFixture) *http.Response {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/oidc/auth", strings.NewReader(conformanceAuthParams().Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		f.h.HandleAuth(w, r, f.sessions)
		return w.Result()
	}

	f := newConformanceFixture(t)
	params := callbackParams(t, post(f))
	assert.NotEmpty(t, params.Get("code"), params.Get("error_description"))

	// Signing in must not lose the POSTed parameters.
	f.sessions = &fakeSessions{err: errors.New("no session")}
	res := post(f)
	assert.Equal(t, http.StatusFound, res.StatusCode)
	require.NotNil(t, f.sessions.reauthURL)
	assert.Equal(t, conformanceAuthParams(), f.sessions.reauthURL.Query())
}

// oidcc-codereuse-30seconds: token endpoint errors used the wrong error codes
// (RFC 6749 5.2): a bad code is invalid_grant, and failed client
// authentication is invalid_client with HTTP 401.
func TestConformance_TokenEndpointErrors(t *testing.T) {
	f := newConformanceFixture(t)

	res, body := f.redeem(t, "not-a-code")
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	assert.Equal(t, "invalid_grant", body["error"])

	params := callbackParams(t, f.authorize(t, conformanceAuthParams()))
	res, body = exchangeCode(t, f.h, params.Get("code"), "wrong-secret")
	assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
	assert.Equal(t, `Basic realm="token"`, res.Header.Get("WWW-Authenticate"))
	assert.Equal(t, "invalid_client", body["error"])
}

// oidcc-userinfo-post-header and oidcc-userinfo-post-body: the UserInfo
// endpoint must support POST (OIDC Core 5.3.1), and accepts the access token
// in a form-encoded body (RFC 6750 2.2).
func TestConformance_UserInfoPost(t *testing.T) {
	f := newConformanceFixture(t)
	sessionToken, err := encodeSessionHandle(f.sessions.handle)
	require.NoError(t, err)
	accessToken := f.h.accessTokenEncryptor.Encrypt(&tokens.AccessTokenPayload{SessionToken: sessionToken})

	t.Run("header", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/oidc/userinfo", nil)
		r.Header.Set("Authorization", "Bearer "+accessToken)
		f.h.HandleUserInfo(w, r)
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.JSONEq(t, `{"sub":"idp-user-id"}`, w.Body.String())
	})
	t.Run("body", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/oidc/userinfo",
			strings.NewReader(url.Values{"access_token": {accessToken}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		f.h.HandleUserInfo(w, r)
		assert.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.JSONEq(t, `{"sub":"idp-user-id"}`, w.Body.String())
	})
	t.Run("invalid token challenge", func(t *testing.T) {
		res := f.userInfo(t, base64.RawStdEncoding.EncodeToString([]byte("bogus")))
		assert.Equal(t, http.StatusUnauthorized, res.StatusCode)
		assert.Equal(t, `Bearer error="invalid_token"`, res.Header.Get("WWW-Authenticate"))
	})
}

// oidcc-codereuse and oidcc-codereuse-30seconds: an authorization code could
// be exchanged any number of times until it expired. RFC 6749 §4.1.2: the
// authorization server MUST deny a second use.
func TestConformance_CodeReuse(t *testing.T) {
	f := newConformanceFixture(t)

	code := callbackParams(t, f.authorize(t, conformanceAuthParams())).Get("code")
	require.NotEmpty(t, code)

	res, body := f.redeem(t, code)
	require.Equal(t, http.StatusOK, res.StatusCode, body)
	accessToken := body["access_token"].(string)
	assert.Equal(t, http.StatusOK, f.userInfo(t, accessToken).StatusCode)

	res, body = f.redeem(t, code)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)
	assert.Equal(t, "invalid_grant", body["error"])

	// The replay revokes the access token issued for the code (RFC 6749
	// §4.1.2 SHOULD): whoever replayed it may hold that token too.
	assert.Equal(t, http.StatusUnauthorized, f.userInfo(t, accessToken).StatusCode)

	// Other codes are unaffected.
	code = callbackParams(t, f.authorize(t, conformanceAuthParams())).Get("code")
	res, body = f.redeem(t, code)
	assert.Equal(t, http.StatusOK, res.StatusCode, body)
}
