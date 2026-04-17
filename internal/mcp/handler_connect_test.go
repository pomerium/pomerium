package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestAppendConnectError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		redirectURL string
		description string
		expected    string
	}{
		{
			name:        "appends error to simple URL",
			redirectURL: "https://example.com/.pomerium/routes",
			description: "discovery failed",
			expected:    "https://example.com/.pomerium/routes?connect_error=discovery+failed",
		},
		{
			name:        "appends error to URL with existing query params",
			redirectURL: "https://example.com/.pomerium/routes?foo=bar",
			description: "upstream error",
			expected:    "https://example.com/.pomerium/routes?connect_error=upstream+error&foo=bar",
		},
		{
			name:        "returns original on unparseable URL",
			redirectURL: "://invalid",
			description: "error",
			expected:    "://invalid",
		},
		{
			name:        "encodes special characters in description",
			redirectURL: "https://example.com/routes",
			description: `client_id domain not allowed: "auth.example.com"`,
			expected:    `https://example.com/routes?connect_error=client_id+domain+not+allowed%3A+%22auth.example.com%22`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendConnectError(tt.redirectURL, tt.description)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsValidRedirectURL(t *testing.T) {
	t.Parallel()

	// Minimal handler with a HostInfo that has known MCP clients.
	srv := &Handler{
		hosts: newHostInfoForTest(nil, map[string]ClientHostInfo{
			"mcp-client.example.com": {},
		}),
	}

	tests := []struct {
		name        string
		requestHost string // Host header on the incoming request
		redirectURL string // redirect_url query parameter
		wantValid   bool
	}{
		{
			name:        "missing redirect_url",
			requestHost: "server.example.com",
			redirectURL: "",
		},
		{
			name:        "non-https scheme",
			requestHost: "server.example.com",
			redirectURL: "http://mcp-client.example.com/callback",
		},
		{
			name:        "no host in redirect_url",
			requestHost: "server.example.com",
			redirectURL: "https:///callback",
		},
		{
			name:        "valid MCP client host",
			requestHost: "server.example.com",
			redirectURL: "https://mcp-client.example.com/callback",
			wantValid:   true,
		},
		{
			name:        "unknown third-party host",
			requestHost: "server.example.com",
			redirectURL: "https://evil.example.com/callback",
		},
		{
			name:        "same host as request (portal redirect)",
			requestHost: "server.example.com",
			redirectURL: "https://server.example.com/.pomerium/routes",
			wantValid:   true,
		},
		{
			name:        "same host with port on request only",
			requestHost: "server.example.com:443",
			redirectURL: "https://server.example.com/.pomerium/routes",
			wantValid:   true,
		},
		{
			name:        "same host with port on redirect only",
			requestHost: "server.example.com",
			redirectURL: "https://server.example.com:443/.pomerium/routes",
			wantValid:   true,
		},
		{
			name:        "same host with matching ports",
			requestHost: "server.example.com:8443",
			redirectURL: "https://server.example.com:8443/.pomerium/routes",
			wantValid:   true,
		},
		{
			name:        "same hostname with different ports matches (stripPort normalizes)",
			requestHost: "server.example.com:8443",
			redirectURL: "https://server.example.com:9443/.pomerium/routes",
			wantValid:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := srv.isValidRedirectURL(tt.redirectURL, tt.requestHost)
			assert.Equal(t, tt.wantValid, got)
		})
	}
}

// TestResolveAutoDiscoveryAuth_ClientSecret verifies that resolveAutoDiscoveryAuth stores
// ClientSecret in the PendingUpstreamAuth when the DCR path returns a client_secret.
func TestResolveAutoDiscoveryAuth_ClientSecret(t *testing.T) {
	t.Parallel()

	// Start an upstream server that serves PRM + AS metadata (no CIMD support → DCR path)
	// and a registration endpoint that returns client_id + client_secret.
	var upstreamURL string
	upstreamSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource/mcp",
			"/.well-known/oauth-protected-resource":
			json.NewEncoder(w).Encode(ProtectedResourceMetadata{
				Resource:             upstreamURL + "/mcp",
				AuthorizationServers: []string{upstreamURL + "/oauth"},
			})
		case "/.well-known/oauth-authorization-server/oauth":
			json.NewEncoder(w).Encode(AuthorizationServerMetadata{
				Issuer:                            upstreamURL + "/oauth",
				AuthorizationEndpoint:             upstreamURL + "/oauth/authorize",
				TokenEndpoint:                     upstreamURL + "/oauth/token",
				RegistrationEndpoint:              upstreamURL + "/oauth/register",
				ResponseTypesSupported:            []string{"code"},
				GrantTypesSupported:               []string{"authorization_code"},
				CodeChallengeMethodsSupported:     []string{"S256"},
				ClientIDMetadataDocumentSupported: false, // no CIMD → triggers DCR
			})
		case "/oauth/register":
			json.NewEncoder(w).Encode(map[string]any{
				"client_id":                "dcr-client-id",
				"client_secret":            "dcr-client-secret",
				"client_secret_expires_at": 0, // 0 means never expires per RFC 7591
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstreamSrv.Close()
	upstreamURL = upstreamSrv.URL

	parsedUpstream, err := url.Parse(upstreamURL)
	require.NoError(t, err)

	// Build a minimal HostInfo with the test server as upstream.
	// UpstreamURL includes /mcp path to match the PRM resource.
	downstreamHost := "127.0.0.1:" + parsedUpstream.Port()
	upstreamMCPURL := upstreamURL + "/mcp"
	hosts := newHostInfoForTest(
		map[string]ServerHostInfo{
			"127.0.0.1": {
				Host:        downstreamHost,
				UpstreamURL: upstreamMCPURL,
				RouteID:     "route-test",
			},
		},
		nil,
	)

	// Mock storage that captures PendingUpstreamAuth
	var capturedPending *oauth21proto.PendingUpstreamAuth
	store := &testConnectStorage{
		getPendingUpstreamAuthFunc: func(_ context.Context, _, _ string) (*oauth21proto.PendingUpstreamAuth, error) {
			return nil, status.Error(codes.NotFound, "not found")
		},
		putPendingUpstreamAuthFunc: func(_ context.Context, pending *oauth21proto.PendingUpstreamAuth) error {
			capturedPending = pending
			return nil
		},
		createAuthorizationRequestFunc: func(_ context.Context, _ *oauth21proto.AuthorizationRequest) (string, error) {
			return "auth-req-123", nil
		},
		deleteAuthorizationRequestFunc: func(_ context.Context, _ string) error {
			return nil
		},
		getUpstreamOAuthClientFunc: func(_ context.Context, _, _ string) (*oauth21proto.UpstreamOAuthClient, error) {
			return nil, fmt.Errorf("not found")
		},
		putUpstreamOAuthClientFunc: func(_ context.Context, _ *oauth21proto.UpstreamOAuthClient) error {
			return nil
		},
	}

	srv := &Handler{
		storage:                 store,
		hosts:                   hosts,
		httpClient:              upstreamSrv.Client(),
		asMetadataDomainMatcher: allowLocalhost(),
	}

	params := &autoDiscoveryAuthParams{
		Hostname:  "127.0.0.1",
		Host:      downstreamHost,
		UserID:    "user-123",
		AuthReqID: "auth-req-123",
		Info: ServerHostInfo{
			RouteID:     "route-test",
			UpstreamURL: upstreamMCPURL,
		},
	}

	authURL, resolveErr := srv.resolveAutoDiscoveryAuth(context.Background(), params)
	require.NoError(t, resolveErr)
	assert.NotEmpty(t, authURL, "should return an authorization URL")

	require.NotNil(t, capturedPending, "PendingUpstreamAuth should have been stored")
	assert.Equal(t, "dcr-client-secret", capturedPending.ClientSecret,
		"ClientSecret must be stored in PendingUpstreamAuth from DCR response")
	assert.Equal(t, "dcr-client-id", capturedPending.ClientId,
		"ClientId should match DCR response")
}

func TestGetOrRegisterUpstreamOAuthClient_EmptyRegistrationEndpoint(t *testing.T) {
	t.Parallel()

	srv := &Handler{
		storage: &testConnectStorage{},
	}

	_, err := srv.getOrRegisterUpstreamOAuthClient(
		context.Background(),
		&discoveryResult{
			Issuer:               "https://auth.example.com",
			RegistrationEndpoint: "", // empty
		},
		"proxy.example.com",
		"https://proxy.example.com/callback",
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registration_endpoint")
}

func TestRegisterWithUpstreamAS_EmptyClientID(t *testing.T) {
	t.Parallel()

	// Mock AS that returns empty client_id — the RFC 7591 parser rejects this
	// before our defensive check, but verify the overall behavior is an error.
	registrationSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"client_id": "",
		})
	}))
	defer registrationSrv.Close()

	srv := &Handler{
		httpClient: registrationSrv.Client(),
		storage: &testConnectStorage{
			getUpstreamOAuthClientFunc: func(_ context.Context, _, _ string) (*oauth21proto.UpstreamOAuthClient, error) {
				return nil, fmt.Errorf("not found")
			},
			putUpstreamOAuthClientFunc: func(_ context.Context, _ *oauth21proto.UpstreamOAuthClient) error {
				return nil
			},
		},
	}

	_, err := srv.getOrRegisterUpstreamOAuthClient(
		context.Background(),
		&discoveryResult{
			Issuer:               "https://auth.example.com",
			RegistrationEndpoint: registrationSrv.URL + "/register",
		},
		"proxy.example.com",
		"https://proxy.example.com/callback",
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_id")
}

// testConnectStorage is a mock implementing HandlerStorage for handler_connect tests.
// Only methods used by the tested code paths are implemented; the rest panic.
type testConnectStorage struct {
	getPendingUpstreamAuthFunc     func(ctx context.Context, userID, host string) (*oauth21proto.PendingUpstreamAuth, error)
	putPendingUpstreamAuthFunc     func(ctx context.Context, pending *oauth21proto.PendingUpstreamAuth) error
	createAuthorizationRequestFunc func(ctx context.Context, req *oauth21proto.AuthorizationRequest) (string, error)
	deleteAuthorizationRequestFunc func(ctx context.Context, id string) error
	getUpstreamOAuthClientFunc     func(ctx context.Context, issuer, downstreamHost string) (*oauth21proto.UpstreamOAuthClient, error)
	putUpstreamOAuthClientFunc     func(ctx context.Context, client *oauth21proto.UpstreamOAuthClient) error
}

func (s *testConnectStorage) GetPendingUpstreamAuth(ctx context.Context, userID, host string) (*oauth21proto.PendingUpstreamAuth, error) {
	if s.getPendingUpstreamAuthFunc != nil {
		return s.getPendingUpstreamAuthFunc(ctx, userID, host)
	}
	panic("unexpected call to GetPendingUpstreamAuth")
}

func (s *testConnectStorage) PutPendingUpstreamAuth(ctx context.Context, pending *oauth21proto.PendingUpstreamAuth) error {
	if s.putPendingUpstreamAuthFunc != nil {
		return s.putPendingUpstreamAuthFunc(ctx, pending)
	}
	panic("unexpected call to PutPendingUpstreamAuth")
}

func (s *testConnectStorage) CreateAuthorizationRequest(ctx context.Context, req *oauth21proto.AuthorizationRequest) (string, error) {
	if s.createAuthorizationRequestFunc != nil {
		return s.createAuthorizationRequestFunc(ctx, req)
	}
	panic("unexpected call to CreateAuthorizationRequest")
}

func (s *testConnectStorage) DeleteAuthorizationRequest(_ context.Context, _ string) error {
	if s.deleteAuthorizationRequestFunc != nil {
		return s.deleteAuthorizationRequestFunc(context.Background(), "")
	}
	panic("unexpected call to DeleteAuthorizationRequest")
}

func (s *testConnectStorage) GetUpstreamOAuthClient(ctx context.Context, issuer, downstreamHost string) (*oauth21proto.UpstreamOAuthClient, error) {
	if s.getUpstreamOAuthClientFunc != nil {
		return s.getUpstreamOAuthClientFunc(ctx, issuer, downstreamHost)
	}
	panic("unexpected call to GetUpstreamOAuthClient")
}

func (s *testConnectStorage) PutUpstreamOAuthClient(ctx context.Context, client *oauth21proto.UpstreamOAuthClient) error {
	if s.putUpstreamOAuthClientFunc != nil {
		return s.putUpstreamOAuthClientFunc(ctx, client)
	}
	panic("unexpected call to PutUpstreamOAuthClient")
}

// Unused interface methods — panic if called unexpectedly.

func (s *testConnectStorage) RegisterClient(context.Context, *rfc7591v1.ClientRegistration) (string, error) {
	panic("unexpected call to RegisterClient")
}

func (s *testConnectStorage) GetClient(context.Context, string) (*rfc7591v1.ClientRegistration, error) {
	panic("unexpected call to GetClient")
}

func (s *testConnectStorage) GetAuthorizationRequest(context.Context, string) (*oauth21proto.AuthorizationRequest, error) {
	panic("unexpected call to GetAuthorizationRequest")
}

func (s *testConnectStorage) GetSession(context.Context, string) (*session.Session, error) {
	panic("unexpected call to GetSession")
}

func (s *testConnectStorage) PutSession(context.Context, *session.Session) error {
	panic("unexpected call to PutSession")
}

func (s *testConnectStorage) PutMCPRefreshToken(context.Context, *oauth21proto.MCPRefreshToken) error {
	panic("unexpected call to PutMCPRefreshToken")
}

func (s *testConnectStorage) GetMCPRefreshToken(context.Context, string) (*oauth21proto.MCPRefreshToken, error) {
	panic("unexpected call to GetMCPRefreshToken")
}

func (s *testConnectStorage) DeleteMCPRefreshToken(context.Context, string) error {
	panic("unexpected call to DeleteMCPRefreshToken")
}

func (s *testConnectStorage) PutUpstreamMCPToken(context.Context, *oauth21proto.UpstreamMCPToken) error {
	panic("unexpected call to PutUpstreamMCPToken")
}

func (s *testConnectStorage) GetUpstreamMCPToken(context.Context, string, string, string) (*oauth21proto.UpstreamMCPToken, error) {
	panic("unexpected call to GetUpstreamMCPToken")
}

func (s *testConnectStorage) DeleteUpstreamMCPToken(context.Context, string, string, string) error {
	panic("unexpected call to DeleteUpstreamMCPToken")
}

func (s *testConnectStorage) DeletePendingUpstreamAuth(context.Context, string, string) error {
	panic("unexpected call to DeletePendingUpstreamAuth")
}

func (s *testConnectStorage) GetPendingUpstreamAuthByState(context.Context, string) (*oauth21proto.PendingUpstreamAuth, error) {
	panic("unexpected call to GetPendingUpstreamAuthByState")
}
