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

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/mcp/extproc"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func TestSelectScopes(t *testing.T) {
	t.Parallel()

	t.Run("www-authenticate scope takes priority", func(t *testing.T) {
		t.Parallel()
		result := selectScopes(
			&WWWAuthenticateParams{Scope: []string{"openid", "profile"}},
			[]string{"read", "write"},
		)
		assert.Equal(t, []string{"openid", "profile"}, result)
	})

	t.Run("falls back to PRM scopes", func(t *testing.T) {
		t.Parallel()
		result := selectScopes(nil, []string{"read", "write"})
		assert.Equal(t, []string{"read", "write"}, result)
	})

	t.Run("nil www-authenticate falls back to PRM scopes", func(t *testing.T) {
		t.Parallel()
		result := selectScopes(
			&WWWAuthenticateParams{},
			[]string{"read"},
		)
		assert.Equal(t, []string{"read"}, result)
	})

	t.Run("returns nil when no scopes available", func(t *testing.T) {
		t.Parallel()
		result := selectScopes(nil, nil)
		assert.Nil(t, result)
	})
}

func TestBuildAuthorizationURL(t *testing.T) {
	t.Parallel()

	t.Run("full params", func(t *testing.T) {
		t.Parallel()
		result := buildAuthorizationURL("https://auth.example.com/authorize", &authorizationURLParams{
			ClientID:            "https://proxy.example.com/.pomerium/mcp/client/metadata.json",
			RedirectURI:         "https://proxy.example.com/.pomerium/mcp/client/oauth/callback",
			Scopes:              []string{"read", "write"},
			State:               "state-123",
			CodeChallenge:       "challenge-abc",
			CodeChallengeMethod: "S256",
			Resource:            "https://api.example.com",
		})
		assert.Contains(t, result, "https://auth.example.com/authorize?")
		assert.Contains(t, result, "client_id=")
		assert.Contains(t, result, "response_type=code")
		assert.Contains(t, result, "redirect_uri=")
		assert.Contains(t, result, "scope=read+write")
		assert.Contains(t, result, "state=state-123")
		assert.Contains(t, result, "code_challenge=challenge-abc")
		assert.Contains(t, result, "code_challenge_method=S256")
		assert.Contains(t, result, "resource=")
	})

	t.Run("no scopes", func(t *testing.T) {
		t.Parallel()
		result := buildAuthorizationURL("https://auth.example.com/authorize", &authorizationURLParams{
			ClientID:            "client-id",
			RedirectURI:         "https://example.com/callback",
			State:               "state-123",
			CodeChallenge:       "challenge",
			CodeChallengeMethod: "S256",
		})
		assert.NotContains(t, result, "scope=")
	})

	t.Run("no resource", func(t *testing.T) {
		t.Parallel()
		result := buildAuthorizationURL("https://auth.example.com/authorize", &authorizationURLParams{
			ClientID:            "client-id",
			RedirectURI:         "https://example.com/callback",
			State:               "state-123",
			CodeChallenge:       "challenge",
			CodeChallengeMethod: "S256",
		})
		assert.NotContains(t, result, "resource=")
	})
}

func TestBuildCallbackURL(t *testing.T) {
	t.Parallel()

	result := buildCallbackURL("proxy.example.com")
	assert.Equal(t, "https://proxy.example.com/.pomerium/mcp/client/oauth/callback", result)
}

func TestBuildClientIDURL(t *testing.T) {
	t.Parallel()

	result := buildClientIDURL("proxy.example.com")
	assert.Equal(t, "https://proxy.example.com/.pomerium/mcp/client/metadata.json", result)
}

func TestGeneratePKCE(t *testing.T) {
	t.Parallel()

	verifier, challenge, err := generatePKCE()
	assert.NoError(t, err)
	assert.NotEmpty(t, verifier)
	assert.NotEmpty(t, challenge)
	assert.NotEqual(t, verifier, challenge)

	// Verify uniqueness
	v2, c2, err := generatePKCE()
	assert.NoError(t, err)
	assert.NotEqual(t, verifier, v2)
	assert.NotEqual(t, challenge, c2)
}

func TestGenerateRandomString(t *testing.T) {
	t.Parallel()

	s1, err := generateRandomString(32)
	assert.NoError(t, err)
	assert.NotEmpty(t, s1)

	s2, err := generateRandomString(32)
	assert.NoError(t, err)
	assert.NotEqual(t, s1, s2)
}

func TestStripPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{"example.com:443", "example.com"},
		{"example.com:8080", "example.com"},
		{"example.com", "example.com"},
		{"[::1]:443", "::1"},
		{"localhost", "localhost"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, stripPort(tt.input), "input: %s", tt.input)
	}
}

func TestStripQueryFromURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{"https://api.example.com/mcp", "https://api.example.com/mcp"},
		{"https://api.example.com/mcp?foo=bar", "https://api.example.com/mcp"},
		{"https://api.example.com/mcp?foo=bar&baz=qux", "https://api.example.com/mcp"},
		{"https://api.example.com", "https://api.example.com"},
		{"https://api.example.com/", "https://api.example.com/"},
		{"https://api.example.com/mcp#fragment", "https://api.example.com/mcp"},
		{"", ""},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, stripQueryFromURL(tt.input), "input: %q", tt.input)
	}
}

func TestNormalizeResourceURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{"https://api.example.com", "https://api.example.com"},
		{"https://api.example.com/", "https://api.example.com"},
		{"https://api.example.com///", "https://api.example.com"},
		{"https://api.example.com/mcp", "https://api.example.com/mcp"},
		{"https://api.example.com/mcp/", "https://api.example.com/mcp"},
		{"", ""},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, normalizeResourceURL(tt.input), "input: %q", tt.input)
	}
}

func TestRunDiscovery_ResourceValidation(t *testing.T) {
	t.Parallel()

	t.Run("matching resource passes validation", func(t *testing.T) {
		t.Parallel()

		var srvURL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-protected-resource":
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             srvURL,
					AuthorizationServers: []string{srvURL + "/oauth"},
				})
			case "/.well-known/oauth-authorization-server/oauth":
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                        srvURL + "/oauth",
					AuthorizationEndpoint:         srvURL + "/oauth/authorize",
					TokenEndpoint:                 srvURL + "/oauth/token",
					ResponseTypesSupported:        []string{"code"},
					GrantTypesSupported:           []string{"authorization_code"},
					CodeChallengeMethodsSupported: []string{"S256"},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		result, err := runDiscovery(context.Background(), srv.Client(), nil, srv.URL, "")
		require.NoError(t, err)
		assert.Equal(t, srv.URL+"/oauth/authorize", result.AuthorizationEndpoint)
		assert.Equal(t, srv.URL+"/oauth/token", result.TokenEndpoint)
		// PRM path: Resource comes from PRM document
		assert.Equal(t, srvURL, result.Resource)
	})

	t.Run("matching resource with trailing slash difference passes", func(t *testing.T) {
		t.Parallel()

		var srvURL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-protected-resource":
				// PRM has trailing slash, upstream server URL does not
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             srvURL + "/",
					AuthorizationServers: []string{srvURL + "/oauth"},
				})
			case "/.well-known/oauth-authorization-server/oauth":
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                        srvURL + "/oauth",
					AuthorizationEndpoint:         srvURL + "/oauth/authorize",
					TokenEndpoint:                 srvURL + "/oauth/token",
					ResponseTypesSupported:        []string{"code"},
					GrantTypesSupported:           []string{"authorization_code"},
					CodeChallengeMethodsSupported: []string{"S256"},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		result, err := runDiscovery(context.Background(), srv.Client(), nil, srv.URL, "")
		require.NoError(t, err)
		assert.Equal(t, srv.URL+"/oauth/token", result.TokenEndpoint)
		// PRM path: Resource comes from PRM document (with trailing slash)
		assert.Equal(t, srvURL+"/", result.Resource)
	})

	t.Run("mismatched resource fails validation", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.URL.Path == "/.well-known/oauth-protected-resource":
				// PRM claims to be for a different resource
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             "https://evil.example.com/mcp",
					AuthorizationServers: []string{"https://evil.example.com/oauth"},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		_, err := runDiscovery(context.Background(), srv.Client(), nil, srv.URL, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match upstream server")
	})

	t.Run("resource metadata from www-authenticate hint also validated", func(t *testing.T) {
		t.Parallel()

		prmServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ProtectedResourceMetadata{
				Resource:             "https://impersonated.example.com",
				AuthorizationServers: []string{"https://evil.example.com/oauth"},
			})
		}))
		defer prmServer.Close()

		wwwAuth := &WWWAuthenticateParams{
			ResourceMetadata: prmServer.URL,
		}
		_, err := runDiscovery(context.Background(), prmServer.Client(), wwwAuth, "https://real.example.com", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match upstream server")
	})

	t.Run("auto-fallback to upstream origin AS metadata when PRM unavailable", func(t *testing.T) {
		t.Parallel()

		// Server serves AS metadata at its own origin but no PRM
		var srvURL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-authorization-server":
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                        srvURL,
					AuthorizationEndpoint:         srvURL + "/authorize",
					TokenEndpoint:                 srvURL + "/token",
					ResponseTypesSupported:        []string{"code"},
					GrantTypesSupported:           []string{"authorization_code"},
					CodeChallengeMethodsSupported: []string{"S256"},
					RegistrationEndpoint:          srvURL + "/register",
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		// No explicit override — should auto-derive from upstream origin
		result, err := runDiscovery(context.Background(), srv.Client(), nil, srv.URL+"/mcp", "")
		require.NoError(t, err)
		assert.Equal(t, srv.URL+"/authorize", result.AuthorizationEndpoint)
		assert.Equal(t, srv.URL+"/token", result.TokenEndpoint)
		assert.Equal(t, srv.URL+"/register", result.RegistrationEndpoint)
		assert.Empty(t, result.ScopesSupported)
		// Fallback path: Resource is the origin (without /mcp path)
		assert.Equal(t, srv.URL, result.Resource)
	})

	t.Run("explicit override AS URL takes precedence over upstream origin", func(t *testing.T) {
		t.Parallel()

		// AS on a different domain than the upstream server
		var asURL string
		asSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-authorization-server":
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                        asURL,
					AuthorizationEndpoint:         asURL + "/authorize",
					TokenEndpoint:                 asURL + "/token",
					ResponseTypesSupported:        []string{"code"},
					GrantTypesSupported:           []string{"authorization_code"},
					CodeChallengeMethodsSupported: []string{"S256"},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer asSrv.Close()
		asURL = asSrv.URL

		// Upstream server returns 404 for everything (PRM and AS metadata)
		upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer upstreamSrv.Close()

		// With explicit override, uses the configured AS URL
		result, err := runDiscovery(context.Background(), asSrv.Client(), nil, upstreamSrv.URL, asSrv.URL)
		require.NoError(t, err)
		assert.Equal(t, asSrv.URL+"/authorize", result.AuthorizationEndpoint)
		assert.Equal(t, asSrv.URL+"/token", result.TokenEndpoint)
		// Fallback path: Resource is the origin of the upstream server
		assert.Equal(t, upstreamSrv.URL, result.Resource)
	})
}

// TestHandleUpstreamResponse_DownstreamHostRouting verifies that HandleUpstreamResponse
// correctly uses the downstream host for HostInfo lookups (UsesAutoDiscovery, getUpstreamServerURL)
// while using the actual upstream URL for PRM discovery.
func TestHandleUpstreamResponse_DownstreamHostRouting(t *testing.T) {
	t.Parallel()

	t.Run("downstream host routes to upstream URL for discovery", func(t *testing.T) {
		t.Parallel()

		// Start an upstream server that serves PRM and AS metadata.
		// Mimics GitHub's pattern: PRM resource includes the /mcp path.
		var upstreamURL string
		upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
					ResponseTypesSupported:            []string{"code"},
					GrantTypesSupported:               []string{"authorization_code"},
					CodeChallengeMethodsSupported:     []string{"S256"},
					ClientIDMetadataDocumentSupported: true,
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer upstreamSrv.Close()
		upstreamURL = upstreamSrv.URL

		// Parse the upstream URL to get host
		parsedUpstream, err := url.Parse(upstreamURL)
		require.NoError(t, err)

		// Build HostInfo: downstream host "proxy.example.com" maps to the test upstream server
		cfg := &config.Config{
			Options: &config.Options{
				Policies: []config.Policy{
					{
						Name: "test-mcp-server",
						From: "https://proxy.example.com",
						To:   config.WeightedURLs{{URL: *parsedUpstream}},
						MCP:  &config.MCP{Server: &config.MCPServer{}},
					},
				},
			},
		}
		hosts := NewHostInfo(cfg, nil)

		// Verify HostInfo is set up correctly
		assert.True(t, hosts.UsesAutoDiscovery("proxy.example.com"),
			"downstream host should use auto-discovery")
		assert.False(t, hosts.UsesAutoDiscovery(parsedUpstream.Hostname()),
			"upstream host should NOT be found in HostInfo")

		// Create a minimal mock storage that returns a session
		var capturedPending *oauth21proto.PendingUpstreamAuth
		store := &testUpstreamAuthStorage{
			getSessionFunc: func(_ context.Context, _ string) (*session.Session, error) {
				return &session.Session{UserId: "user-123"}, nil
			},
			putPendingUpstreamAuthFunc: func(_ context.Context, pending *oauth21proto.PendingUpstreamAuth) error {
				capturedPending = pending
				return nil
			},
		}

		handler := &UpstreamAuthHandler{
			storage:    store,
			hosts:      hosts,
			httpClient: upstreamSrv.Client(),
		}

		routeCtx := &extproc.RouteContext{
			RouteID:   "route-123",
			SessionID: "session-456",
			IsMCP:     true,
		}

		// Call HandleUpstreamResponse with the DOWNSTREAM host (what ext_proc now passes)
		action, err := handler.HandleUpstreamResponse(
			context.Background(),
			routeCtx,
			"proxy.example.com", // downstream host
			upstreamURL+"/mcp",  // originalURL with upstream host
			401,                 // upstream returned 401
			"",                  // no www-authenticate
		)

		require.NoError(t, err)
		require.NotNil(t, action, "should return an action for the upstream auth flow")
		assert.Contains(t, action.WWWAuthenticate, "resource_metadata=",
			"action should contain a WWW-Authenticate header pointing to Pomerium's PRM")
		assert.Contains(t, action.WWWAuthenticate, "proxy.example.com",
			"WWW-Authenticate should reference the downstream host")

		// Verify the pending auth state
		require.NotNil(t, capturedPending)
		assert.Equal(t, upstreamURL, capturedPending.UpstreamServer,
			"pending auth should store the base upstream server URL for token storage keys")
		assert.Contains(t, capturedPending.RedirectUri, "proxy.example.com",
			"callback redirect URI should use the downstream host (served by Pomerium)")
		assert.Contains(t, capturedPending.ClientId, "proxy.example.com",
			"client ID (CIMD URL) should use the downstream host (served by Pomerium)")
		assert.Equal(t, upstreamURL+"/mcp", capturedPending.OriginalUrl,
			"original URL should be the full upstream URL with path")
		assert.Equal(t, "proxy.example.com", capturedPending.DownstreamHost,
			"downstream_host should be stored for Authorize endpoint lookups")
		assert.NotEmpty(t, capturedPending.PkceChallenge,
			"PKCE challenge should be stored for Authorize endpoint")
	})

	t.Run("upstream host is not found in HostInfo", func(t *testing.T) {
		t.Parallel()

		// HostInfo only knows about downstream hosts
		cfg := &config.Config{
			Options: &config.Options{
				Policies: []config.Policy{
					{
						Name: "test-mcp-server",
						From: "https://proxy.example.com",
						MCP:  &config.MCP{Server: &config.MCPServer{}},
					},
				},
			},
		}
		hosts := NewHostInfo(cfg, nil)

		handler := &UpstreamAuthHandler{
			hosts: hosts,
		}

		routeCtx := &extproc.RouteContext{
			RouteID: "route-123",
			IsMCP:   true,
		}

		// If someone passes the upstream host (bug scenario), UsesAutoDiscovery returns false
		action, err := handler.HandleUpstreamResponse(
			context.Background(),
			routeCtx,
			"api.upstream.com", // upstream host — not in HostInfo
			"https://api.upstream.com/mcp",
			401,
			"",
		)
		require.NoError(t, err)
		assert.Nil(t, action, "should return nil when host not found in HostInfo")
	})
}

// testUpstreamAuthStorage is a minimal mock implementing handlerStorage for testing
// HandleUpstreamResponse. Only the methods used by the 401 handling path are implemented.
type testUpstreamAuthStorage struct {
	getSessionFunc             func(ctx context.Context, id string) (*session.Session, error)
	putPendingUpstreamAuthFunc func(ctx context.Context, pending *oauth21proto.PendingUpstreamAuth) error
}

func (s *testUpstreamAuthStorage) GetSession(ctx context.Context, id string) (*session.Session, error) {
	if s.getSessionFunc != nil {
		return s.getSessionFunc(ctx, id)
	}
	return nil, fmt.Errorf("not found")
}

func (s *testUpstreamAuthStorage) PutPendingUpstreamAuth(ctx context.Context, pending *oauth21proto.PendingUpstreamAuth) error {
	if s.putPendingUpstreamAuthFunc != nil {
		return s.putPendingUpstreamAuthFunc(ctx, pending)
	}
	return nil
}

// Unused interface methods — panic if called unexpectedly.
func (s *testUpstreamAuthStorage) RegisterClient(context.Context, *rfc7591v1.ClientRegistration) (string, error) {
	panic("unexpected call to RegisterClient")
}

func (s *testUpstreamAuthStorage) GetClient(context.Context, string) (*rfc7591v1.ClientRegistration, error) {
	panic("unexpected call to GetClient")
}

func (s *testUpstreamAuthStorage) CreateAuthorizationRequest(context.Context, *oauth21proto.AuthorizationRequest) (string, error) {
	panic("unexpected call to CreateAuthorizationRequest")
}

func (s *testUpstreamAuthStorage) GetAuthorizationRequest(context.Context, string) (*oauth21proto.AuthorizationRequest, error) {
	panic("unexpected call to GetAuthorizationRequest")
}

func (s *testUpstreamAuthStorage) DeleteAuthorizationRequest(context.Context, string) error {
	panic("unexpected call to DeleteAuthorizationRequest")
}

func (s *testUpstreamAuthStorage) PutSession(context.Context, *session.Session) error {
	panic("unexpected call to PutSession")
}

func (s *testUpstreamAuthStorage) StoreUpstreamOAuth2Token(context.Context, string, string, *oauth21proto.TokenResponse) error {
	panic("unexpected call to StoreUpstreamOAuth2Token")
}

func (s *testUpstreamAuthStorage) GetUpstreamOAuth2Token(context.Context, string, string) (*oauth21proto.TokenResponse, error) {
	panic("unexpected call to GetUpstreamOAuth2Token")
}

func (s *testUpstreamAuthStorage) DeleteUpstreamOAuth2Token(context.Context, string, string) error {
	panic("unexpected call to DeleteUpstreamOAuth2Token")
}

func (s *testUpstreamAuthStorage) PutMCPRefreshToken(context.Context, *oauth21proto.MCPRefreshToken) error {
	panic("unexpected call to PutMCPRefreshToken")
}

func (s *testUpstreamAuthStorage) GetMCPRefreshToken(context.Context, string) (*oauth21proto.MCPRefreshToken, error) {
	panic("unexpected call to GetMCPRefreshToken")
}

func (s *testUpstreamAuthStorage) DeleteMCPRefreshToken(context.Context, string) error {
	panic("unexpected call to DeleteMCPRefreshToken")
}

func (s *testUpstreamAuthStorage) PutUpstreamMCPToken(context.Context, *oauth21proto.UpstreamMCPToken) error {
	panic("unexpected call to PutUpstreamMCPToken")
}

func (s *testUpstreamAuthStorage) GetUpstreamMCPToken(context.Context, string, string, string) (*oauth21proto.UpstreamMCPToken, error) {
	panic("unexpected call to GetUpstreamMCPToken")
}

func (s *testUpstreamAuthStorage) DeleteUpstreamMCPToken(context.Context, string, string, string) error {
	panic("unexpected call to DeleteUpstreamMCPToken")
}

func (s *testUpstreamAuthStorage) GetPendingUpstreamAuth(context.Context, string, string) (*oauth21proto.PendingUpstreamAuth, error) {
	panic("unexpected call to GetPendingUpstreamAuth")
}

func (s *testUpstreamAuthStorage) DeletePendingUpstreamAuth(context.Context, string, string) error {
	panic("unexpected call to DeletePendingUpstreamAuth")
}

func (s *testUpstreamAuthStorage) GetPendingUpstreamAuthByState(context.Context, string) (*oauth21proto.PendingUpstreamAuth, error) {
	panic("unexpected call to GetPendingUpstreamAuthByState")
}

func (s *testUpstreamAuthStorage) GetUpstreamOAuthClient(_ context.Context, _, _ string) (*oauth21proto.UpstreamOAuthClient, error) {
	return nil, fmt.Errorf("not found")
}

func (s *testUpstreamAuthStorage) PutUpstreamOAuthClient(_ context.Context, _ *oauth21proto.UpstreamOAuthClient) error {
	return nil
}

// TestHandle401_ClientRegistrationStrategy verifies the CIMD check + DCR fallback logic.
func TestHandle401_ClientRegistrationStrategy(t *testing.T) {
	t.Parallel()

	// newMockUpstream creates a test server that serves PRM and AS metadata.
	// asMetadataExtra is merged into the AS metadata response.
	newMockUpstream := func(asMetadataExtra func(baseURL string) map[string]any) (*httptest.Server, *string) {
		var srvURL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-protected-resource":
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             srvURL,
					AuthorizationServers: []string{srvURL + "/oauth"},
				})
			case "/.well-known/oauth-authorization-server/oauth":
				asm := map[string]any{
					"issuer":                           srvURL + "/oauth",
					"authorization_endpoint":           srvURL + "/oauth/authorize",
					"token_endpoint":                   srvURL + "/oauth/token",
					"response_types_supported":         []string{"code"},
					"grant_types_supported":            []string{"authorization_code"},
					"code_challenge_methods_supported": []string{"S256"},
				}
				if asMetadataExtra != nil {
					for k, v := range asMetadataExtra(srvURL) {
						asm[k] = v
					}
				}
				json.NewEncoder(w).Encode(asm)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		srvURL = srv.URL
		return srv, &srvURL
	}

	newHandler := func(upstreamSrv *httptest.Server, upstreamURL string) (*UpstreamAuthHandler, **oauth21proto.PendingUpstreamAuth) {
		parsedUpstream, _ := url.Parse(upstreamURL)
		cfg := &config.Config{
			Options: &config.Options{
				Policies: []config.Policy{
					{
						Name: "test-mcp-server",
						From: "https://proxy.example.com",
						To:   config.WeightedURLs{{URL: *parsedUpstream}},
						MCP:  &config.MCP{Server: &config.MCPServer{}},
					},
				},
			},
		}
		hosts := NewHostInfo(cfg, nil)

		var capturedPending *oauth21proto.PendingUpstreamAuth
		store := &testUpstreamAuthStorage{
			getSessionFunc: func(_ context.Context, _ string) (*session.Session, error) {
				return &session.Session{UserId: "user-123"}, nil
			},
			putPendingUpstreamAuthFunc: func(_ context.Context, pending *oauth21proto.PendingUpstreamAuth) error {
				capturedPending = pending
				return nil
			},
		}

		handler := &UpstreamAuthHandler{
			storage:    store,
			hosts:      hosts,
			httpClient: upstreamSrv.Client(),
		}
		return handler, &capturedPending
	}

	routeCtx := &extproc.RouteContext{
		RouteID:   "route-123",
		SessionID: "session-456",
		IsMCP:     true,
	}

	t.Run("CIMD supported — uses CIMD URL", func(t *testing.T) {
		t.Parallel()

		upstreamSrv, upstreamURL := newMockUpstream(func(_ string) map[string]any {
			return map[string]any{
				"client_id_metadata_document_supported": true,
			}
		})
		defer upstreamSrv.Close()

		handler, capturedPending := newHandler(upstreamSrv, *upstreamURL)

		action, err := handler.HandleUpstreamResponse(
			context.Background(), routeCtx,
			"proxy.example.com", *upstreamURL, 401, "",
		)
		require.NoError(t, err)
		require.NotNil(t, action)

		require.NotNil(t, *capturedPending)
		assert.Contains(t, (*capturedPending).ClientId, "proxy.example.com",
			"client_id should be CIMD URL with downstream host")
		assert.Contains(t, (*capturedPending).ClientId, "metadata.json",
			"client_id should be a CIMD URL")
		assert.Empty(t, (*capturedPending).ClientSecret,
			"client_secret should be empty for CIMD")
	})

	t.Run("DCR fallback — registers dynamically", func(t *testing.T) {
		t.Parallel()

		// Start a separate DCR registration endpoint
		dcrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{
				"client_id":     "registered-123",
				"client_secret": "secret-456",
			})
		}))
		defer dcrSrv.Close()

		upstreamSrv, upstreamURL := newMockUpstream(func(_ string) map[string]any {
			return map[string]any{
				"client_id_metadata_document_supported": false,
				"registration_endpoint":                 dcrSrv.URL + "/register",
			}
		})
		defer upstreamSrv.Close()

		// The handler's httpClient needs to be able to reach both servers.
		// Since dcrSrv is a separate server, we use http.DefaultClient for this test.
		parsedUpstream, _ := url.Parse(*upstreamURL)
		cfg := &config.Config{
			Options: &config.Options{
				Policies: []config.Policy{
					{
						Name: "test-mcp-server",
						From: "https://proxy.example.com",
						To:   config.WeightedURLs{{URL: *parsedUpstream}},
						MCP:  &config.MCP{Server: &config.MCPServer{}},
					},
				},
			},
		}
		hosts := NewHostInfo(cfg, nil)

		var capturedPending *oauth21proto.PendingUpstreamAuth
		store := &testUpstreamAuthStorage{
			getSessionFunc: func(_ context.Context, _ string) (*session.Session, error) {
				return &session.Session{UserId: "user-123"}, nil
			},
			putPendingUpstreamAuthFunc: func(_ context.Context, pending *oauth21proto.PendingUpstreamAuth) error {
				capturedPending = pending
				return nil
			},
		}

		// Use a transport that can reach both test servers
		handler := &UpstreamAuthHandler{
			storage:    store,
			hosts:      hosts,
			httpClient: &http.Client{},
		}

		action, err := handler.HandleUpstreamResponse(
			context.Background(), routeCtx,
			"proxy.example.com", *upstreamURL, 401, "",
		)
		require.NoError(t, err)
		require.NotNil(t, action)

		require.NotNil(t, capturedPending)
		assert.Equal(t, "registered-123", capturedPending.ClientId,
			"client_id should be from DCR response")
		assert.Equal(t, "secret-456", capturedPending.ClientSecret,
			"client_secret should be from DCR response")
	})

	t.Run("neither supported — returns error", func(t *testing.T) {
		t.Parallel()

		upstreamSrv, upstreamURL := newMockUpstream(func(_ string) map[string]any {
			// No CIMD support, no registration_endpoint
			return map[string]any{
				"client_id_metadata_document_supported": false,
			}
		})
		defer upstreamSrv.Close()

		handler, _ := newHandler(upstreamSrv, *upstreamURL)

		action, err := handler.HandleUpstreamResponse(
			context.Background(), routeCtx,
			"proxy.example.com", *upstreamURL, 401, "",
		)
		require.Error(t, err)
		assert.Nil(t, action)
		assert.Contains(t, err.Error(), "does not support")
	})
}

func TestRegisterWithUpstreamAS(t *testing.T) {
	t.Parallel()

	t.Run("successful registration", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			var body map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			assert.Equal(t, "Test Client", body["client_name"])
			assert.Equal(t, []any{"https://proxy.example.com/callback"}, body["redirect_uris"])
			assert.Equal(t, []any{"authorization_code"}, body["grant_types"])
			assert.Equal(t, "none", body["token_endpoint_auth_method"])

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{
				"client_id":     "new-client-id",
				"client_secret": "new-client-secret",
			})
		}))
		defer srv.Close()

		clientID, clientSecret, err := registerWithUpstreamAS(
			context.Background(), srv.Client(),
			srv.URL, "https://proxy.example.com/callback", "Test Client",
		)
		require.NoError(t, err)
		assert.Equal(t, "new-client-id", clientID)
		assert.Equal(t, "new-client-secret", clientSecret)
	})

	t.Run("registration returns 400", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error": "invalid_client_metadata"}`))
		}))
		defer srv.Close()

		_, _, err := registerWithUpstreamAS(
			context.Background(), srv.Client(),
			srv.URL, "https://proxy.example.com/callback", "Test Client",
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "registration endpoint returned 400")
	})

	t.Run("response missing client_id", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{
				"client_secret": "secret-only",
			})
		}))
		defer srv.Close()

		_, _, err := registerWithUpstreamAS(
			context.Background(), srv.Client(),
			srv.URL, "https://proxy.example.com/callback", "Test Client",
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing client_id")
	})
}

func TestRunUpstreamOAuthSetup(t *testing.T) {
	t.Parallel()

	t.Run("success with CIMD", func(t *testing.T) {
		t.Parallel()

		var srvURL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-protected-resource":
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             srvURL,
					AuthorizationServers: []string{srvURL + "/oauth"},
				})
			case "/.well-known/oauth-authorization-server/oauth":
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                            srvURL + "/oauth",
					AuthorizationEndpoint:             srvURL + "/oauth/authorize",
					TokenEndpoint:                     srvURL + "/oauth/token",
					ResponseTypesSupported:            []string{"code"},
					GrantTypesSupported:               []string{"authorization_code"},
					CodeChallengeMethodsSupported:     []string{"S256"},
					ClientIDMetadataDocumentSupported: true,
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		result, err := runUpstreamOAuthSetup(context.Background(), &upstreamOAuthSetupParams{
			HTTPClient:     srv.Client(),
			UpstreamURL:    srvURL,
			ResourceURL:    srvURL,
			DownstreamHost: "proxy.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Contains(t, result.ClientID, "proxy.example.com")
		assert.Contains(t, result.ClientID, "metadata.json")
		assert.Empty(t, result.ClientSecret)
		assert.Contains(t, result.RedirectURI, "proxy.example.com")
		assert.Equal(t, srvURL+"/oauth/authorize", result.Discovery.AuthorizationEndpoint)
		assert.Equal(t, srvURL+"/oauth/token", result.Discovery.TokenEndpoint)
	})

	t.Run("no PRM returns error", func(t *testing.T) {
		t.Parallel()

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		result, err := runUpstreamOAuthSetup(context.Background(), &upstreamOAuthSetupParams{
			HTTPClient:     srv.Client(),
			UpstreamURL:    srv.URL,
			ResourceURL:    srv.URL,
			DownstreamHost: "proxy.example.com",
		})
		require.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("DCR fallback", func(t *testing.T) {
		t.Parallel()

		dcrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{
				"client_id":     "dcr-client",
				"client_secret": "dcr-secret",
			})
		}))
		defer dcrSrv.Close()

		var srvURL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-protected-resource":
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             srvURL,
					AuthorizationServers: []string{srvURL + "/oauth"},
				})
			case "/.well-known/oauth-authorization-server/oauth":
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                            srvURL + "/oauth",
					AuthorizationEndpoint:             srvURL + "/oauth/authorize",
					TokenEndpoint:                     srvURL + "/oauth/token",
					ResponseTypesSupported:            []string{"code"},
					GrantTypesSupported:               []string{"authorization_code"},
					CodeChallengeMethodsSupported:     []string{"S256"},
					ClientIDMetadataDocumentSupported: false,
					RegistrationEndpoint:              dcrSrv.URL + "/register",
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		// Use a default client that can reach both test servers
		result, err := runUpstreamOAuthSetup(context.Background(), &upstreamOAuthSetupParams{
			HTTPClient:     &http.Client{},
			UpstreamURL:    srvURL,
			ResourceURL:    srvURL,
			DownstreamHost: "proxy.example.com",
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "dcr-client", result.ClientID)
		assert.Equal(t, "dcr-secret", result.ClientSecret)
	})

	t.Run("neither CIMD nor DCR returns error", func(t *testing.T) {
		t.Parallel()

		var srvURL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-protected-resource":
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             srvURL,
					AuthorizationServers: []string{srvURL + "/oauth"},
				})
			case "/.well-known/oauth-authorization-server/oauth":
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                            srvURL + "/oauth",
					AuthorizationEndpoint:             srvURL + "/oauth/authorize",
					TokenEndpoint:                     srvURL + "/oauth/token",
					ResponseTypesSupported:            []string{"code"},
					GrantTypesSupported:               []string{"authorization_code"},
					CodeChallengeMethodsSupported:     []string{"S256"},
					ClientIDMetadataDocumentSupported: false,
					// No registration_endpoint
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		result, err := runUpstreamOAuthSetup(context.Background(), &upstreamOAuthSetupParams{
			HTTPClient:     srv.Client(),
			UpstreamURL:    srvURL,
			ResourceURL:    srvURL,
			DownstreamHost: "proxy.example.com",
		})
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "does not support")
	})

	t.Run("with WWW-Authenticate scopes", func(t *testing.T) {
		t.Parallel()

		var srvURL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-protected-resource":
				json.NewEncoder(w).Encode(ProtectedResourceMetadata{
					Resource:             srvURL,
					AuthorizationServers: []string{srvURL + "/oauth"},
					ScopesSupported:      []string{"read", "write"},
				})
			case "/.well-known/oauth-authorization-server/oauth":
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                            srvURL + "/oauth",
					AuthorizationEndpoint:             srvURL + "/oauth/authorize",
					TokenEndpoint:                     srvURL + "/oauth/token",
					ResponseTypesSupported:            []string{"code"},
					GrantTypesSupported:               []string{"authorization_code"},
					CodeChallengeMethodsSupported:     []string{"S256"},
					ClientIDMetadataDocumentSupported: true,
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()
		srvURL = srv.URL

		result, err := runUpstreamOAuthSetup(context.Background(), &upstreamOAuthSetupParams{
			HTTPClient:     srv.Client(),
			UpstreamURL:    srvURL,
			ResourceURL:    srvURL,
			DownstreamHost: "proxy.example.com",
			WWWAuth:        &WWWAuthenticateParams{Scope: []string{"admin"}},
		})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, []string{"admin"}, result.Scopes, "WWW-Authenticate scopes should take priority")
	})
}
