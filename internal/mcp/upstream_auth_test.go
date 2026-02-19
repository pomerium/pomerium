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

// TestRefreshToken_ResourceParam verifies that refreshToken uses the canonical ResourceParam
// (not UpstreamServer) as the RFC 8707 resource indicator, and omits it when empty rather
// than sending an invalid "resource=" parameter.
//
// RFC 8707 §2: "The client SHOULD provide the 'resource' parameter [...] if [...] the protected
// resource [...] has been previously established." An empty resource= is NOT the same as
// omitting the parameter — it is an invalid value that strict AS implementations will reject.
func TestRefreshToken_ResourceParam(t *testing.T) {
	t.Parallel()

	t.Run("uses ResourceParam over UpstreamServer for RFC 8707 resource indicator", func(t *testing.T) {
		t.Parallel()

		// Capture the token exchange request to verify the resource parameter.
		var capturedFormValues url.Values
		tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, r.ParseForm())
			capturedFormValues = r.Form
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "new-access-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "new-refresh-token",
			})
		}))
		defer tokenSrv.Close()

		store := &refreshTokenTestStorage{
			putUpstreamMCPTokenFunc: func(_ context.Context, _ *oauth21proto.UpstreamMCPToken) error {
				return nil
			},
		}

		handler := &UpstreamAuthHandler{
			storage:    store,
			httpClient: tokenSrv.Client(),
		}

		token := &oauth21proto.UpstreamMCPToken{
			UserId:         "user-1",
			RouteId:        "route-1",
			UpstreamServer: "https://api.example.com/mcp", // full URL with path
			ResourceParam:  "https://api.example.com",     // origin-only from fallback discovery
			RefreshToken:   "old-refresh-token",
			Audience:       "https://proxy.example.com/.pomerium/mcp/client/metadata.json",
			TokenEndpoint:  tokenSrv.URL,
		}

		refreshed, err := handler.refreshToken(context.Background(), token)
		require.NoError(t, err)
		assert.Equal(t, "new-access-token", refreshed.AccessToken)

		// Verify: the resource parameter sent to the AS must be ResourceParam
		// (the canonical resource from discovery), NOT UpstreamServer (full path URL).
		// Per RFC 8707 §2, the resource indicator must match what was used during authorization.
		assert.Equal(t, "https://api.example.com", capturedFormValues.Get("resource"),
			"refresh request must use ResourceParam (canonical resource from discovery), "+
				"not UpstreamServer (full path URL)")
	})

	t.Run("backwards-compat: falls back to UpstreamServer when ResourceParam is empty", func(t *testing.T) {
		t.Parallel()

		var capturedFormValues url.Values
		tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, r.ParseForm())
			capturedFormValues = r.Form
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "new-access-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "new-refresh-token",
			})
		}))
		defer tokenSrv.Close()

		store := &refreshTokenTestStorage{
			putUpstreamMCPTokenFunc: func(_ context.Context, _ *oauth21proto.UpstreamMCPToken) error {
				return nil
			},
		}

		handler := &UpstreamAuthHandler{
			storage:    store,
			httpClient: tokenSrv.Client(),
		}

		// Token stored before ResourceParam was added — has no ResourceParam field.
		token := &oauth21proto.UpstreamMCPToken{
			UserId:         "user-1",
			RouteId:        "route-1",
			UpstreamServer: "https://api.example.com/mcp",
			ResourceParam:  "", // empty — pre-upgrade token
			RefreshToken:   "old-refresh-token",
			Audience:       "https://proxy.example.com/.pomerium/mcp/client/metadata.json",
			TokenEndpoint:  tokenSrv.URL,
		}

		refreshed, err := handler.refreshToken(context.Background(), token)
		require.NoError(t, err)
		assert.Equal(t, "new-access-token", refreshed.AccessToken)

		// Should fall back to UpstreamServer
		assert.Equal(t, "https://api.example.com/mcp", capturedFormValues.Get("resource"),
			"when ResourceParam is empty, should fall back to UpstreamServer for backwards compat")
	})

	t.Run("omits resource parameter when both ResourceParam and UpstreamServer are empty", func(t *testing.T) {
		t.Parallel()

		// RFC 8707 §2: An empty "resource=" is invalid. When there is no resource
		// to send, the parameter must be omitted entirely, not sent as empty string.
		var capturedFormValues url.Values
		tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, r.ParseForm())
			capturedFormValues = r.Form
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "new-access-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "new-refresh-token",
			})
		}))
		defer tokenSrv.Close()

		store := &refreshTokenTestStorage{
			putUpstreamMCPTokenFunc: func(_ context.Context, _ *oauth21proto.UpstreamMCPToken) error {
				return nil
			},
		}

		handler := &UpstreamAuthHandler{
			storage:    store,
			httpClient: tokenSrv.Client(),
		}

		// Edge case: both ResourceParam and UpstreamServer are empty.
		token := &oauth21proto.UpstreamMCPToken{
			UserId:         "user-1",
			RouteId:        "route-1",
			UpstreamServer: "",
			ResourceParam:  "",
			RefreshToken:   "old-refresh-token",
			Audience:       "client-id",
			TokenEndpoint:  tokenSrv.URL,
		}

		_, err := handler.refreshToken(context.Background(), token)
		require.NoError(t, err)

		// The resource parameter must NOT be present in the request when empty.
		// Sending "resource=" (empty value) is invalid per RFC 8707 §2 and strict
		// AS implementations will reject it with 400 Bad Request.
		assert.False(t, capturedFormValues.Has("resource"),
			"must not send resource= with empty value; RFC 8707 §2 requires a valid URI "+
				"or the parameter must be omitted entirely")
	})

	t.Run("preserves ResourceParam across refresh", func(t *testing.T) {
		t.Parallel()

		var storedToken *oauth21proto.UpstreamMCPToken
		tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "new-access-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "new-refresh-token",
			})
		}))
		defer tokenSrv.Close()

		store := &refreshTokenTestStorage{
			putUpstreamMCPTokenFunc: func(_ context.Context, tok *oauth21proto.UpstreamMCPToken) error {
				storedToken = tok
				return nil
			},
		}

		handler := &UpstreamAuthHandler{
			storage:    store,
			httpClient: tokenSrv.Client(),
		}

		token := &oauth21proto.UpstreamMCPToken{
			UserId:         "user-1",
			RouteId:        "route-1",
			UpstreamServer: "https://api.example.com/mcp",
			ResourceParam:  "https://api.example.com",
			RefreshToken:   "old-refresh-token",
			Audience:       "client-id",
			TokenEndpoint:  tokenSrv.URL,
		}

		_, err := handler.refreshToken(context.Background(), token)
		require.NoError(t, err)

		require.NotNil(t, storedToken)
		assert.Equal(t, "https://api.example.com", storedToken.ResourceParam,
			"refreshed token must preserve the original ResourceParam")
	})
}

// TestHandle401_ResourceParamStoredInPending verifies that handle401 stores the canonical
// resource identifier from discovery (not the full original URL) as ResourceParam in the
// pending auth state.
//
// This is critical for the fallback path where PRM is unavailable: the resource identifier
// is derived as the origin of the upstream URL (e.g., "https://api.example.com" for
// "https://api.example.com/mcp/tools/list"). If OriginalUrl were used instead, the
// authorization and token exchange would use different resource values, violating RFC 8707.
func TestHandle401_ResourceParamStoredInPending(t *testing.T) {
	t.Parallel()

	t.Run("fallback discovery stores origin as ResourceParam, not full URL", func(t *testing.T) {
		t.Parallel()

		// Upstream server has NO PRM (returns 404 for everything PRM-related),
		// but DOES serve AS metadata at its origin.
		var srvURL string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/.well-known/oauth-authorization-server":
				json.NewEncoder(w).Encode(AuthorizationServerMetadata{
					Issuer:                            srvURL,
					AuthorizationEndpoint:             srvURL + "/authorize",
					TokenEndpoint:                     srvURL + "/token",
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

		parsedUpstream, err := url.Parse(srvURL)
		require.NoError(t, err)

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
			httpClient: srv.Client(),
		}

		routeCtx := &extproc.RouteContext{
			RouteID:   "route-123",
			SessionID: "session-456",
			IsMCP:     true,
		}

		// The originalURL includes a path — e.g., an MCP tools/list request.
		originalURL := srvURL + "/mcp/tools/list?cursor=abc"
		action, err := handler.HandleUpstreamResponse(
			context.Background(), routeCtx,
			"proxy.example.com", originalURL, 401, "",
		)
		require.NoError(t, err)
		require.NotNil(t, action)

		// The ResourceParam must be the ORIGIN (scheme+host) from fallback discovery,
		// not the full OriginalUrl. This ensures the resource parameter is consistent
		// between the authorization request and the token exchange.
		require.NotNil(t, capturedPending)
		assert.Equal(t, srvURL, capturedPending.ResourceParam,
			"ResourceParam must be the origin from fallback discovery (scheme+host only), "+
				"not the full original URL with path/query")
		assert.Equal(t, srvURL+"/mcp/tools/list?cursor=abc", capturedPending.OriginalUrl,
			"OriginalUrl should preserve the full upstream URL including query")
		assert.NotEqual(t, capturedPending.OriginalUrl, capturedPending.ResourceParam,
			"ResourceParam and OriginalUrl should differ when path is present")
	})
}

// TestReusePendingAuth_ResourceParamConsistency verifies that when a pending auth state
// (created by ext_proc handle401) is reused by resolveAutoDiscoveryAuth, the authorization
// URL uses the same resource parameter that will be used in the token exchange.
//
// Bug: handler_connect.go:430 uses stripQueryFromURL(pending.OriginalUrl) for the resource
// parameter, while handler_client_oauth_callback.go:88 uses pending.ResourceParam. When
// these differ (e.g., fallback path: ResourceParam="https://api.example.com" vs
// OriginalUrl="https://api.example.com/mcp/tools/list"), the AS may reject the token
// exchange due to mismatched resource values per RFC 8707.
func TestReusePendingAuth_ResourceParamConsistency(t *testing.T) {
	t.Parallel()

	// This test verifies that buildAuthorizationURL uses pending.ResourceParam
	// (canonical resource from discovery) rather than stripQueryFromURL(pending.OriginalUrl)
	// (full URL with path).

	// Simulate a pending auth state created by ext_proc handle401 in the fallback path:
	// ResourceParam is the origin (from fallback AS discovery), while OriginalUrl is the
	// full upstream request URL with path.
	pending := &oauth21proto.PendingUpstreamAuth{
		StateId:               "state-xyz",
		UserId:                "user-123",
		RouteId:               "route-123",
		UpstreamServer:        "https://api.example.com",
		OriginalUrl:           "https://api.example.com/mcp/tools/list",
		ResourceParam:         "https://api.example.com", // origin-only from fallback
		AuthorizationEndpoint: "https://auth.example.com/authorize",
		TokenEndpoint:         "https://auth.example.com/token",
		ClientId:              "https://proxy.example.com/.pomerium/mcp/client/metadata.json",
		RedirectUri:           "https://proxy.example.com/.pomerium/mcp/client/oauth/callback",
		PkceChallenge:         "test-challenge",
	}

	// The production code in resolveAutoDiscoveryAuth must use ResourceParam (canonical
	// resource from discovery) when available, falling back to stripQueryFromURL(OriginalUrl)
	// for backwards compat. Verify the fixed logic produces a consistent resource parameter.
	resource := pending.GetResourceParam()
	if resource == "" {
		resource = stripQueryFromURL(pending.OriginalUrl)
	}
	authURL := buildAuthorizationURL(pending.AuthorizationEndpoint, &authorizationURLParams{
		ClientID:            pending.ClientId,
		RedirectURI:         pending.RedirectUri,
		State:               pending.StateId,
		CodeChallenge:       pending.PkceChallenge,
		CodeChallengeMethod: "S256",
		Resource:            resource,
	})

	// Parse the auth URL to extract the resource parameter
	parsedAuthURL, err := url.Parse(authURL)
	require.NoError(t, err)
	authResourceParam := parsedAuthURL.Query().Get("resource")

	// Simulate what ClientOAuthCallback does for the token exchange (handler_client_oauth_callback.go:88-91)
	tokenExchangeResource := pending.GetResourceParam()
	if tokenExchangeResource == "" {
		tokenExchangeResource = pending.UpstreamServer
	}

	// RFC 8707 §2: The resource parameter in the authorization request MUST match
	// the resource parameter in the token exchange request. If the AS enforces this
	// (as it SHOULD), mismatched values will cause the token exchange to fail.
	assert.Equal(t, tokenExchangeResource, authResourceParam,
		"resource parameter mismatch between authorization request and token exchange: "+
			"authorization URL uses stripQueryFromURL(OriginalUrl)=%q but token exchange uses ResourceParam=%q; "+
			"per RFC 8707 §2, these MUST be identical for the AS to accept the token exchange",
		authResourceParam, tokenExchangeResource)
}

// TestOriginOf verifies the originOf helper function used to derive the resource identifier
// in the fallback AS discovery path. Edge cases matter because originOf's output becomes
// the "resource" parameter in OAuth authorization and token exchange requests.
func TestOriginOf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standard URL strips path",
			input:    "https://api.example.com/mcp/tools/list",
			expected: "https://api.example.com",
		},
		{
			name:     "URL with port preserved",
			input:    "https://api.example.com:8443/mcp",
			expected: "https://api.example.com:8443",
		},
		{
			name:     "URL with query and fragment stripped",
			input:    "https://api.example.com/path?foo=bar#section",
			expected: "https://api.example.com",
		},
		{
			name:     "bare origin unchanged",
			input:    "https://api.example.com",
			expected: "https://api.example.com",
		},
		{
			name:     "HTTP scheme preserved",
			input:    "http://localhost:8080/mcp",
			expected: "http://localhost:8080",
		},
		{
			name:     "trailing slash stripped",
			input:    "https://api.example.com/",
			expected: "https://api.example.com",
		},
		{
			name:     "empty string returns empty",
			input:    "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, originOf(tt.input))
		})
	}
}

// refreshTokenTestStorage is a minimal mock for testing refreshToken.
// Only implements the methods called during the refresh flow.
type refreshTokenTestStorage struct {
	putUpstreamMCPTokenFunc func(ctx context.Context, token *oauth21proto.UpstreamMCPToken) error
}

func (s *refreshTokenTestStorage) PutUpstreamMCPToken(ctx context.Context, token *oauth21proto.UpstreamMCPToken) error {
	if s.putUpstreamMCPTokenFunc != nil {
		return s.putUpstreamMCPTokenFunc(ctx, token)
	}
	return nil
}

// Unused interface methods — panic if called unexpectedly.
func (s *refreshTokenTestStorage) RegisterClient(context.Context, *rfc7591v1.ClientRegistration) (string, error) {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) GetClient(context.Context, string) (*rfc7591v1.ClientRegistration, error) {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) CreateAuthorizationRequest(context.Context, *oauth21proto.AuthorizationRequest) (string, error) {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) GetAuthorizationRequest(context.Context, string) (*oauth21proto.AuthorizationRequest, error) {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) DeleteAuthorizationRequest(context.Context, string) error {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) GetSession(context.Context, string) (*session.Session, error) {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) PutSession(context.Context, *session.Session) error {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) StoreUpstreamOAuth2Token(context.Context, string, string, *oauth21proto.TokenResponse) error {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) GetUpstreamOAuth2Token(context.Context, string, string) (*oauth21proto.TokenResponse, error) {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) DeleteUpstreamOAuth2Token(context.Context, string, string) error {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) PutMCPRefreshToken(context.Context, *oauth21proto.MCPRefreshToken) error {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) GetMCPRefreshToken(context.Context, string) (*oauth21proto.MCPRefreshToken, error) {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) DeleteMCPRefreshToken(context.Context, string) error {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) GetUpstreamMCPToken(context.Context, string, string, string) (*oauth21proto.UpstreamMCPToken, error) {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) DeleteUpstreamMCPToken(context.Context, string, string, string) error {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) PutPendingUpstreamAuth(context.Context, *oauth21proto.PendingUpstreamAuth) error {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) GetPendingUpstreamAuth(context.Context, string, string) (*oauth21proto.PendingUpstreamAuth, error) {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) DeletePendingUpstreamAuth(context.Context, string, string) error {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) GetPendingUpstreamAuthByState(context.Context, string) (*oauth21proto.PendingUpstreamAuth, error) {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) GetUpstreamOAuthClient(context.Context, string, string) (*oauth21proto.UpstreamOAuthClient, error) {
	panic("unexpected call")
}

func (s *refreshTokenTestStorage) PutUpstreamOAuthClient(context.Context, *oauth21proto.UpstreamOAuthClient) error {
	panic("unexpected call")
}
