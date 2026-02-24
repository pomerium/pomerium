package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

// makeTestJWT creates a signed JWT with the given claims for testing.
func makeTestJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	key := []byte("test-secret-key-for-unit-tests!!")
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, nil)
	require.NoError(t, err)
	token, err := josejwt.Signed(signer).Claims(claims).CompactSerialize()
	require.NoError(t, err)
	return token
}

// testClaims returns standard test JWT claims with session and user ID.
func testClaims() map[string]any {
	return map[string]any{
		"sid": "test-session-id",
		"sub": "test-user-id",
	}
}

// mockHandlerStorage implements handlerStorage for unit tests.
// Each method delegates to its corresponding function field if set,
// otherwise returns a NotFound gRPC error.
type mockHandlerStorage struct {
	mu sync.Mutex

	RegisterClientFn                func(ctx context.Context, req *rfc7591v1.ClientRegistration) (string, error)
	GetClientFn                     func(ctx context.Context, id string) (*rfc7591v1.ClientRegistration, error)
	CreateAuthorizationRequestFn    func(ctx context.Context, req *oauth21proto.AuthorizationRequest) (string, error)
	GetAuthorizationRequestFn       func(ctx context.Context, id string) (*oauth21proto.AuthorizationRequest, error)
	DeleteAuthorizationRequestFn    func(ctx context.Context, id string) error
	GetSessionFn                    func(ctx context.Context, id string) (*session.Session, error)
	GetServiceAccountFn             func(ctx context.Context, id string) (*user.ServiceAccount, error)
	PutSessionFn                    func(ctx context.Context, s *session.Session) error
	StoreUpstreamOAuth2TokenFn      func(ctx context.Context, host, userID string, token *oauth21proto.TokenResponse) error
	GetUpstreamOAuth2TokenFn        func(ctx context.Context, host, userID string) (*oauth21proto.TokenResponse, error)
	DeleteUpstreamOAuth2TokenFn     func(ctx context.Context, host, userID string) error
	PutMCPRefreshTokenFn            func(ctx context.Context, token *oauth21proto.MCPRefreshToken) error
	GetMCPRefreshTokenFn            func(ctx context.Context, id string) (*oauth21proto.MCPRefreshToken, error)
	DeleteMCPRefreshTokenFn         func(ctx context.Context, id string) error
	PutUpstreamMCPTokenFn           func(ctx context.Context, token *oauth21proto.UpstreamMCPToken) error
	GetUpstreamMCPTokenFn           func(ctx context.Context, userID, routeID, upstreamServer string) (*oauth21proto.UpstreamMCPToken, error)
	DeleteUpstreamMCPTokenFn        func(ctx context.Context, userID, routeID, upstreamServer string) error
	PutPendingUpstreamAuthFn        func(ctx context.Context, pending *oauth21proto.PendingUpstreamAuth) error
	GetPendingUpstreamAuthFn        func(ctx context.Context, userID, host string) (*oauth21proto.PendingUpstreamAuth, error)
	DeletePendingUpstreamAuthFn     func(ctx context.Context, userID, host string) error
	GetPendingUpstreamAuthByStateFn func(ctx context.Context, stateID string) (*oauth21proto.PendingUpstreamAuth, error)
	GetUpstreamOAuthClientFn        func(ctx context.Context, issuer, downstreamHost string) (*oauth21proto.UpstreamOAuthClient, error)
	PutUpstreamOAuthClientFn        func(ctx context.Context, client *oauth21proto.UpstreamOAuthClient) error

	// Calls tracks method invocations for assertions.
	Calls []string
}

func (m *mockHandlerStorage) record(method string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls = append(m.Calls, method)
}

func (m *mockHandlerStorage) hasCalled(method string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.Calls {
		if c == method {
			return true
		}
	}
	return false
}

var errNotImpl = status.Error(codes.NotFound, "not found")

func (m *mockHandlerStorage) RegisterClient(ctx context.Context, req *rfc7591v1.ClientRegistration) (string, error) {
	m.record("RegisterClient")
	if m.RegisterClientFn != nil {
		return m.RegisterClientFn(ctx, req)
	}
	return "", errNotImpl
}

func (m *mockHandlerStorage) GetClient(ctx context.Context, id string) (*rfc7591v1.ClientRegistration, error) {
	m.record("GetClient")
	if m.GetClientFn != nil {
		return m.GetClientFn(ctx, id)
	}
	return nil, errNotImpl
}

func (m *mockHandlerStorage) CreateAuthorizationRequest(ctx context.Context, req *oauth21proto.AuthorizationRequest) (string, error) {
	m.record("CreateAuthorizationRequest")
	if m.CreateAuthorizationRequestFn != nil {
		return m.CreateAuthorizationRequestFn(ctx, req)
	}
	return "", errNotImpl
}

func (m *mockHandlerStorage) GetAuthorizationRequest(ctx context.Context, id string) (*oauth21proto.AuthorizationRequest, error) {
	m.record("GetAuthorizationRequest")
	if m.GetAuthorizationRequestFn != nil {
		return m.GetAuthorizationRequestFn(ctx, id)
	}
	return nil, errNotImpl
}

func (m *mockHandlerStorage) DeleteAuthorizationRequest(ctx context.Context, id string) error {
	m.record("DeleteAuthorizationRequest:" + id)
	if m.DeleteAuthorizationRequestFn != nil {
		return m.DeleteAuthorizationRequestFn(ctx, id)
	}
	return nil
}

func (m *mockHandlerStorage) GetSession(ctx context.Context, id string) (*session.Session, error) {
	m.record("GetSession")
	if m.GetSessionFn != nil {
		return m.GetSessionFn(ctx, id)
	}
	return nil, errNotImpl
}

func (m *mockHandlerStorage) GetServiceAccount(ctx context.Context, id string) (*user.ServiceAccount, error) {
	m.record("GetServiceAccount")
	if m.GetServiceAccountFn != nil {
		return m.GetServiceAccountFn(ctx, id)
	}
	return nil, errNotImpl
}

func (m *mockHandlerStorage) PutSession(ctx context.Context, s *session.Session) error {
	m.record("PutSession")
	if m.PutSessionFn != nil {
		return m.PutSessionFn(ctx, s)
	}
	return nil
}

func (m *mockHandlerStorage) StoreUpstreamOAuth2Token(ctx context.Context, host, userID string, token *oauth21proto.TokenResponse) error {
	m.record("StoreUpstreamOAuth2Token")
	if m.StoreUpstreamOAuth2TokenFn != nil {
		return m.StoreUpstreamOAuth2TokenFn(ctx, host, userID, token)
	}
	return nil
}

func (m *mockHandlerStorage) GetUpstreamOAuth2Token(ctx context.Context, host, userID string) (*oauth21proto.TokenResponse, error) {
	m.record("GetUpstreamOAuth2Token")
	if m.GetUpstreamOAuth2TokenFn != nil {
		return m.GetUpstreamOAuth2TokenFn(ctx, host, userID)
	}
	return nil, errNotImpl
}

func (m *mockHandlerStorage) DeleteUpstreamOAuth2Token(ctx context.Context, host, userID string) error {
	m.record("DeleteUpstreamOAuth2Token")
	if m.DeleteUpstreamOAuth2TokenFn != nil {
		return m.DeleteUpstreamOAuth2TokenFn(ctx, host, userID)
	}
	return nil
}

func (m *mockHandlerStorage) PutMCPRefreshToken(ctx context.Context, token *oauth21proto.MCPRefreshToken) error {
	m.record("PutMCPRefreshToken")
	if m.PutMCPRefreshTokenFn != nil {
		return m.PutMCPRefreshTokenFn(ctx, token)
	}
	return nil
}

func (m *mockHandlerStorage) GetMCPRefreshToken(ctx context.Context, id string) (*oauth21proto.MCPRefreshToken, error) {
	m.record("GetMCPRefreshToken")
	if m.GetMCPRefreshTokenFn != nil {
		return m.GetMCPRefreshTokenFn(ctx, id)
	}
	return nil, errNotImpl
}

func (m *mockHandlerStorage) DeleteMCPRefreshToken(ctx context.Context, id string) error {
	m.record("DeleteMCPRefreshToken")
	if m.DeleteMCPRefreshTokenFn != nil {
		return m.DeleteMCPRefreshTokenFn(ctx, id)
	}
	return nil
}

func (m *mockHandlerStorage) PutUpstreamMCPToken(ctx context.Context, token *oauth21proto.UpstreamMCPToken) error {
	m.record("PutUpstreamMCPToken")
	if m.PutUpstreamMCPTokenFn != nil {
		return m.PutUpstreamMCPTokenFn(ctx, token)
	}
	return nil
}

func (m *mockHandlerStorage) GetUpstreamMCPToken(ctx context.Context, userID, routeID, upstreamServer string) (*oauth21proto.UpstreamMCPToken, error) {
	m.record("GetUpstreamMCPToken")
	if m.GetUpstreamMCPTokenFn != nil {
		return m.GetUpstreamMCPTokenFn(ctx, userID, routeID, upstreamServer)
	}
	return nil, errNotImpl
}

func (m *mockHandlerStorage) DeleteUpstreamMCPToken(ctx context.Context, userID, routeID, upstreamServer string) error {
	m.record("DeleteUpstreamMCPToken")
	if m.DeleteUpstreamMCPTokenFn != nil {
		return m.DeleteUpstreamMCPTokenFn(ctx, userID, routeID, upstreamServer)
	}
	return nil
}

func (m *mockHandlerStorage) PutPendingUpstreamAuth(ctx context.Context, pending *oauth21proto.PendingUpstreamAuth) error {
	m.record("PutPendingUpstreamAuth")
	if m.PutPendingUpstreamAuthFn != nil {
		return m.PutPendingUpstreamAuthFn(ctx, pending)
	}
	return nil
}

func (m *mockHandlerStorage) GetPendingUpstreamAuth(ctx context.Context, userID, host string) (*oauth21proto.PendingUpstreamAuth, error) {
	m.record("GetPendingUpstreamAuth")
	if m.GetPendingUpstreamAuthFn != nil {
		return m.GetPendingUpstreamAuthFn(ctx, userID, host)
	}
	return nil, errNotImpl
}

func (m *mockHandlerStorage) DeletePendingUpstreamAuth(ctx context.Context, userID, host string) error {
	m.record("DeletePendingUpstreamAuth:" + userID + ":" + host)
	if m.DeletePendingUpstreamAuthFn != nil {
		return m.DeletePendingUpstreamAuthFn(ctx, userID, host)
	}
	return nil
}

func (m *mockHandlerStorage) GetPendingUpstreamAuthByState(ctx context.Context, stateID string) (*oauth21proto.PendingUpstreamAuth, error) {
	m.record("GetPendingUpstreamAuthByState")
	if m.GetPendingUpstreamAuthByStateFn != nil {
		return m.GetPendingUpstreamAuthByStateFn(ctx, stateID)
	}
	return nil, errNotImpl
}

func (m *mockHandlerStorage) GetUpstreamOAuthClient(ctx context.Context, issuer, downstreamHost string) (*oauth21proto.UpstreamOAuthClient, error) {
	m.record("GetUpstreamOAuthClient")
	if m.GetUpstreamOAuthClientFn != nil {
		return m.GetUpstreamOAuthClientFn(ctx, issuer, downstreamHost)
	}
	return nil, errNotImpl
}

func (m *mockHandlerStorage) PutUpstreamOAuthClient(ctx context.Context, client *oauth21proto.UpstreamOAuthClient) error {
	m.record("PutUpstreamOAuthClient")
	if m.PutUpstreamOAuthClientFn != nil {
		return m.PutUpstreamOAuthClientFn(ctx, client)
	}
	return nil
}

// autoDiscoveryConfig returns a config with an auto-discovery MCP server route
// and a matching MCP client route for redirect URL validation.
func autoDiscoveryConfig() *config.Config {
	return &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					Name: "Auto Discovery Server",
					From: "https://auto.example.com",
					To:   mustParseWeightedURLs([]string{"https://upstream.example.com"}),
					MCP:  &config.MCP{Server: &config.MCPServer{}},
				},
				{
					Name: "MCP Client",
					From: "https://client.example.com",
					MCP:  &config.MCP{Client: &config.MCPClient{}},
				},
			},
		},
	}
}

// mustParseWeightedURLs parses URL strings into config.WeightedURLs.
func mustParseWeightedURLs(urls []string) config.WeightedURLs {
	var result config.WeightedURLs
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			panic(fmt.Sprintf("failed to parse URL %q: %v", raw, err))
		}
		result = append(result, config.WeightedURL{URL: *u})
	}
	return result
}

// Finding 1: DisconnectRoutes should delete PendingUpstreamAuth record (not just the index).
// Currently only deletes the index, leaving orphaned records with PKCE verifiers and client secrets.
func TestDisconnectRoutes_DeletesPendingUpstreamAuth(t *testing.T) {
	cfg := autoDiscoveryConfig()
	storage := &mockHandlerStorage{
		// Return a pending auth with known stateID when looked up by user+host
		GetPendingUpstreamAuthFn: func(_ context.Context, _, _ string) (*oauth21proto.PendingUpstreamAuth, error) {
			return &oauth21proto.PendingUpstreamAuth{
				StateId:   "pending-state-123",
				UserId:    "test-user-id",
				ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
			}, nil
		},
		DeleteUpstreamMCPTokenFn: func(_ context.Context, _, _, _ string) error {
			return nil
		},
		DeletePendingUpstreamAuthFn: func(_ context.Context, _, _ string) error {
			return nil
		},
		GetUpstreamMCPTokenFn: func(_ context.Context, _, _, _ string) (*oauth21proto.UpstreamMCPToken, error) {
			return nil, errNotImpl
		},
	}

	handler := &Handler{
		hosts:   NewHostInfo(cfg, nil),
		storage: storage,
	}

	body := `{"routes": ["https://auto.example.com"]}`
	req := httptest.NewRequest(http.MethodPost, "https://auto.example.com/.pomerium/mcp/routes/disconnect", strings.NewReader(body))
	req.Host = "auto.example.com"
	req.Header.Set(httputil.HeaderPomeriumJWTAssertion, makeTestJWT(t, testClaims()))
	rr := httptest.NewRecorder()

	handler.DisconnectRoutes(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	// The key assertion: DeletePendingUpstreamAuth should be called with user+host composite key
	assert.True(t, storage.hasCalled("DeletePendingUpstreamAuth:test-user-id:auto.example.com"),
		"DisconnectRoutes should delete the PendingUpstreamAuth record by user+host composite key. "+
			"Calls: %v", storage.Calls)
}

// Finding 2: /authorize should clean up authReqID when resolveAutoDiscoveryAuth fails.
// Currently the auth request leaks in storage.
func TestAuthorize_CleansUpAuthReqOnDiscoveryError(t *testing.T) {
	cfg := autoDiscoveryConfig()
	storage := &mockHandlerStorage{
		// Return a test client when looked up
		GetClientFn: func(_ context.Context, _ string) (*rfc7591v1.ClientRegistration, error) {
			return &rfc7591v1.ClientRegistration{
				ResponseMetadata: &rfc7591v1.Metadata{
					RedirectUris:            []string{"https://client.example.com/callback"},
					TokenEndpointAuthMethod: proto.String(rfc7591v1.TokenEndpointAuthMethodNone),
				},
			}, nil
		},
		// CreateAuthorizationRequest succeeds with known ID
		CreateAuthorizationRequestFn: func(_ context.Context, _ *oauth21proto.AuthorizationRequest) (string, error) {
			return "test-auth-req-id", nil
		},
		// No existing upstream MCP token
		GetUpstreamMCPTokenFn: func(_ context.Context, _, _, _ string) (*oauth21proto.UpstreamMCPToken, error) {
			return nil, status.Error(codes.NotFound, "not found")
		},
		// Return a valid pending auth (to trigger PutPendingUpstreamAuth path)
		GetPendingUpstreamAuthFn: func(_ context.Context, _, _ string) (*oauth21proto.PendingUpstreamAuth, error) {
			return &oauth21proto.PendingUpstreamAuth{
				StateId:               "pending-state-xyz",
				UserId:                "test-user-id",
				AuthorizationEndpoint: "https://as.example.com/authorize",
				ClientId:              "upstream-client",
				RedirectUri:           "https://auto.example.com/.pomerium/mcp/client/oauth/callback",
				PkceChallenge:         "test-challenge",
				ExpiresAt:             timestamppb.New(time.Now().Add(time.Hour)),
			}, nil
		},
		// PutPendingUpstreamAuth FAILS — this causes resolveAutoDiscoveryAuth to return error
		PutPendingUpstreamAuthFn: func(_ context.Context, _ *oauth21proto.PendingUpstreamAuth) error {
			return fmt.Errorf("simulated storage failure")
		},
		// DeleteAuthorizationRequest should be called for cleanup
		DeleteAuthorizationRequestFn: func(_ context.Context, _ string) error {
			return nil
		},
	}

	handler := &Handler{
		hosts:   NewHostInfo(cfg, nil),
		storage: storage,
	}

	req := httptest.NewRequest(http.MethodGet,
		"https://auto.example.com/.pomerium/mcp/authorize?"+
			"response_type=code&"+
			"client_id=test-client&"+
			"redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&"+
			"code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&"+
			"code_challenge_method=S256&"+
			"state=test-state",
		nil)
	req.Host = "auto.example.com"
	req.Header.Set(httputil.HeaderPomeriumJWTAssertion, makeTestJWT(t, testClaims()))
	rr := httptest.NewRecorder()

	handler.Authorize(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)

	// The key assertion: authReqID should be cleaned up on error
	assert.True(t, storage.hasCalled("DeleteAuthorizationRequest:test-auth-req-id"),
		"Authorize should clean up the AuthorizationRequest when resolveAutoDiscoveryAuth fails. "+
			"Calls: %v", storage.Calls)
}

// strictResponseWriter enforces that headers set after WriteHeader are NOT visible
// in the response, matching real net/http behavior (httptest.ResponseRecorder doesn't enforce this).
type strictResponseWriter struct {
	rr            *httptest.ResponseRecorder
	headerWritten bool
	frozenHeaders http.Header // snapshot of headers at WriteHeader time
}

func newStrictResponseWriter() *strictResponseWriter {
	return &strictResponseWriter{rr: httptest.NewRecorder()}
}

func (w *strictResponseWriter) Header() http.Header {
	return w.rr.Header()
}

func (w *strictResponseWriter) WriteHeader(code int) {
	w.headerWritten = true
	w.frozenHeaders = w.rr.Header().Clone()
	w.rr.WriteHeader(code)
}

func (w *strictResponseWriter) Write(b []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}
	return w.rr.Write(b)
}

// Finding 5: Response headers (Cache-Control, Pragma, Expires) must be set BEFORE WriteHeader.
// Currently they're set after WriteHeader and silently dropped in real net/http.
func TestListRoutes_CacheControlHeaders(t *testing.T) {
	cfg := autoDiscoveryConfig()
	storage := &mockHandlerStorage{
		GetUpstreamMCPTokenFn: func(_ context.Context, _, _, _ string) (*oauth21proto.UpstreamMCPToken, error) {
			return nil, status.Error(codes.NotFound, "not found")
		},
	}

	handler := &Handler{
		hosts:   NewHostInfo(cfg, nil),
		storage: storage,
	}

	req := httptest.NewRequest(http.MethodGet, "https://auto.example.com/.pomerium/mcp/routes", nil)
	req.Host = "auto.example.com"
	req.Header.Set(httputil.HeaderPomeriumJWTAssertion, makeTestJWT(t, testClaims()))
	sw := newStrictResponseWriter()

	handler.ListRoutes(sw, req)

	assert.Equal(t, http.StatusOK, sw.rr.Code)

	// Check frozenHeaders (captured at WriteHeader time). Headers set AFTER WriteHeader
	// won't appear here, matching real net/http behavior.
	assert.Contains(t, sw.frozenHeaders.Get("Cache-Control"), "no-store",
		"Cache-Control header must be set before WriteHeader")
	assert.Equal(t, "no-cache", sw.frozenHeaders.Get("Pragma"),
		"Pragma header must be set before WriteHeader")
	assert.Equal(t, "0", sw.frozenHeaders.Get("Expires"),
		"Expires header must be set before WriteHeader")
}

// Finding 6: resolveAutoDiscoveryAuth panics on nil ExpiresAt in PendingUpstreamAuth.
// The check `pending.ExpiresAt.AsTime().After(time.Now())` dereferences nil.
func TestResolveAutoDiscoveryAuth_NilExpiresAt(t *testing.T) {
	storage := &mockHandlerStorage{
		// Return pending auth with nil ExpiresAt
		GetPendingUpstreamAuthFn: func(_ context.Context, _, _ string) (*oauth21proto.PendingUpstreamAuth, error) {
			return &oauth21proto.PendingUpstreamAuth{
				StateId:               "pending-no-expiry",
				UserId:                "test-user-id",
				AuthorizationEndpoint: "https://as.example.com/authorize",
				ClientId:              "upstream-client",
				RedirectUri:           "https://auto.example.com/.pomerium/mcp/client/oauth/callback",
				PkceChallenge:         "test-challenge",
				OriginalUrl:           "https://upstream.example.com",
				ExpiresAt:             nil, // nil — should not panic
			}, nil
		},
		PutPendingUpstreamAuthFn: func(_ context.Context, _ *oauth21proto.PendingUpstreamAuth) error {
			return nil
		},
	}

	handler := &Handler{
		storage:    storage,
		httpClient: http.DefaultClient,
	}

	// Should not panic
	assert.NotPanics(t, func() {
		authURL, err := handler.resolveAutoDiscoveryAuth(context.Background(), &autoDiscoveryAuthParams{
			Hostname:  "auto.example.com",
			Host:      "auto.example.com",
			UserID:    "test-user-id",
			AuthReqID: "test-auth-req",
			Info: ServerHostInfo{
				RouteID:     "route-1",
				UpstreamURL: "https://upstream.example.com",
			},
		})
		// Should succeed — nil ExpiresAt means "no expiry" (treat as valid)
		assert.NoError(t, err)
		assert.NotEmpty(t, authURL, "should return auth URL when pending auth has no expiry")
	}, "resolveAutoDiscoveryAuth should not panic on nil ExpiresAt")
}

// Finding 7: DisconnectRoutes silently skips auto-discovery routes with incomplete info
// (empty RouteID or UpstreamURL) without incrementing skippedCount or logging.
func TestDisconnectRoutes_IncompleteRouteInfo(t *testing.T) {
	// Create config where To is empty so UpstreamURL will be ""
	cfg := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					Name: "Incomplete Route",
					From: "https://incomplete.example.com",
					// No To targets — UpstreamURL will be empty
					MCP: &config.MCP{Server: &config.MCPServer{}},
				},
			},
		},
	}
	storage := &mockHandlerStorage{
		GetUpstreamMCPTokenFn: func(_ context.Context, _, _, _ string) (*oauth21proto.UpstreamMCPToken, error) {
			return nil, errNotImpl
		},
	}

	handler := &Handler{
		hosts:   NewHostInfo(cfg, nil),
		storage: storage,
	}

	body := `{"routes": ["https://incomplete.example.com"]}`
	req := httptest.NewRequest(http.MethodPost, "https://incomplete.example.com/.pomerium/mcp/routes/disconnect", strings.NewReader(body))
	req.Host = "incomplete.example.com"
	req.Header.Set(httputil.HeaderPomeriumJWTAssertion, makeTestJWT(t, testClaims()))
	rr := httptest.NewRecorder()

	handler.DisconnectRoutes(rr, req)

	// Should return 200 with route list (not crash)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Should NOT have tried to delete a token with empty keys
	assert.False(t, storage.hasCalled("DeleteUpstreamMCPToken"),
		"Should not attempt to delete upstream MCP token when route info is incomplete")
}

// Finding 3 (partial): verify that GetServerHostInfo ok is checked.
// This tests the connect handler when UpstreamURL is empty, ensuring it doesn't
// silently skip the OAuth flow and redirect as if the user is connected.
func TestConnectGet_AutoDiscoveryEmptyUpstreamURL(t *testing.T) {
	// Create config where To is empty so UpstreamURL will be ""
	cfg := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					Name: "Incomplete Route",
					From: "https://incomplete.example.com",
					// No To targets — UpstreamURL will be empty
					MCP: &config.MCP{Server: &config.MCPServer{}},
				},
				{
					Name: "MCP Client",
					From: "https://client.example.com",
					MCP:  &config.MCP{Client: &config.MCPClient{}},
				},
			},
		},
	}
	storage := &mockHandlerStorage{
		CreateAuthorizationRequestFn: func(_ context.Context, _ *oauth21proto.AuthorizationRequest) (string, error) {
			return "test-auth-req-id", nil
		},
		GetPendingUpstreamAuthFn: func(_ context.Context, _, _ string) (*oauth21proto.PendingUpstreamAuth, error) {
			return nil, status.Error(codes.NotFound, "not found")
		},
		DeleteAuthorizationRequestFn: func(_ context.Context, _ string) error {
			return nil
		},
	}

	handler := &Handler{
		hosts:      NewHostInfo(cfg, nil),
		storage:    storage,
		httpClient: http.DefaultClient,
	}

	req := httptest.NewRequest(http.MethodGet,
		"https://incomplete.example.com/.pomerium/mcp/connect?redirect_url=https%3A%2F%2Fclient.example.com%2Fdone",
		nil)
	req.Host = "incomplete.example.com"
	req.Header.Set(httputil.HeaderPomeriumJWTAssertion, makeTestJWT(t, testClaims()))
	rr := httptest.NewRecorder()

	handler.ConnectGet(rr, req)

	// After fix: route with empty UpstreamURL on auto-discovery path should return 500
	// (the route is misconfigured — no upstream to connect to)
	assert.Equal(t, http.StatusInternalServerError, rr.Code,
		"ConnectGet should return 500 for auto-discovery route with empty UpstreamURL")
}

// Verify the serverInfo struct fields don't have unnecessary json:"-" tags on unexported fields
// and the struct alignment is consistent (finding from code-simplifier).
func TestServerInfoJSON(t *testing.T) {
	info := serverInfo{
		Name:            "Test",
		Description:     "Test Server",
		URL:             "https://test.example.com",
		Connected:       true,
		NeedsOauth:      true,
		host:            "test.example.com",
		routeID:         "route-1",
		upstreamURL:     "https://upstream.example.com",
		hasStaticConfig: false,
	}

	data, err := json.Marshal(info)
	require.NoError(t, err)

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))

	// Unexported fields should not appear in JSON
	assert.NotContains(t, m, "host")
	assert.NotContains(t, m, "routeID")
	assert.NotContains(t, m, "upstreamURL")
	assert.NotContains(t, m, "hasStaticConfig")

	// Exported fields should be present
	assert.Equal(t, "Test", m["name"])
	assert.Equal(t, true, m["connected"])
	assert.Equal(t, true, m["needs_oauth"])
}
