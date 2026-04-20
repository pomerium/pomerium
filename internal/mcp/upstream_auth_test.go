package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/mcp/extproc"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

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

		// Create a minimal mock storage
		var capturedPending *oauth21proto.PendingUpstreamAuth
		store := &testUpstreamAuthStorage{
			putPendingUpstreamAuthFunc: func(_ context.Context, pending *oauth21proto.PendingUpstreamAuth) error {
				capturedPending = pending
				return nil
			},
		}

		handler := &UpstreamAuthHandler{
			storage:                 store,
			hosts:                   hosts,
			httpClient:              upstreamSrv.Client(),
			asMetadataDomainMatcher: allowLocalhost(),
		}

		routeCtx := &extproc.RouteContext{
			RouteID: "route-123",
			UserID:  "user-123",
			IsMCP:   true,
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
		assert.Contains(t, action.WWWAuthenticate,
			`resource_metadata="https://proxy.example.com/.well-known/oauth-protected-resource/mcp"`,
			"resource_metadata URI should include the request path per RFC 9728 §4")

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

// testUpstreamAuthStorage is a minimal mock implementing HandlerStorage for testing
// HandleUpstreamResponse. Only the methods used by the 401 handling path are implemented.
type testUpstreamAuthStorage struct {
	getSessionFunc             func(ctx context.Context, id string) (*session.Session, error)
	putPendingUpstreamAuthFunc func(ctx context.Context, pending *oauth21proto.PendingUpstreamAuth) error
}

func (s *testUpstreamAuthStorage) GetSession(ctx context.Context, id string) (*session.Session, error) {
	if s.getSessionFunc != nil {
		return s.getSessionFunc(ctx, id)
	}
	return nil, status.Error(codes.NotFound, "session not found")
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
			ClientId:       "https://proxy.example.com/.pomerium/mcp/client/metadata.json",
			TokenEndpoint:  tokenSrv.URL,
		}

		refreshed, err := doRefreshUpstreamMCPToken(context.Background(), handler.storage, handler.httpClient, token, "")
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
			ClientId:       "https://proxy.example.com/.pomerium/mcp/client/metadata.json",
			TokenEndpoint:  tokenSrv.URL,
		}

		refreshed, err := doRefreshUpstreamMCPToken(context.Background(), handler.storage, handler.httpClient, token, "")
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
			ClientId:       "client-id",
			TokenEndpoint:  tokenSrv.URL,
		}

		_, err := doRefreshUpstreamMCPToken(context.Background(), handler.storage, handler.httpClient, token, "")
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
			ClientId:       "client-id",
			TokenEndpoint:  tokenSrv.URL,
		}

		_, err := doRefreshUpstreamMCPToken(context.Background(), handler.storage, handler.httpClient, token, "")
		require.NoError(t, err)

		require.NotNil(t, storedToken)
		assert.Equal(t, "https://api.example.com", storedToken.ResourceParam,
			"refreshed token must preserve the original ResourceParam")
	})
}

// TestRefreshToken_ClientSecret verifies that refreshToken correctly includes or omits
// client_secret from the token endpoint request based on the configClientSecret parameter,
// and that the secret is NOT stored in the refreshed token (single source of truth is config).
func TestRefreshToken_ClientSecret(t *testing.T) {
	t.Parallel()

	t.Run("includes client_secret when configClientSecret is set", func(t *testing.T) {
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

		var storedToken *oauth21proto.UpstreamMCPToken
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
			UpstreamServer: "https://api.example.com",
			RefreshToken:   "old-refresh-token",
			ClientId:       "google-client-id",
			TokenEndpoint:  tokenSrv.URL,
		}

		refreshed, err := doRefreshUpstreamMCPToken(context.Background(), handler.storage, handler.httpClient, token, "google-client-secret")
		require.NoError(t, err)
		assert.Equal(t, "new-access-token", refreshed.AccessToken)

		// Verify client_secret was sent to the token endpoint
		assert.Equal(t, "google-client-secret", capturedFormValues.Get("client_secret"),
			"refresh request must include client_secret from config for pre-registered clients")

		// Verify client_secret is NOT stored in the refreshed token (single source of truth is config)
		require.NotNil(t, storedToken)
		assert.Empty(t, storedToken.ClientSecret,
			"refreshed token must NOT store client_secret (read from config at refresh time)")
	})

	t.Run("omits client_secret when configClientSecret is empty", func(t *testing.T) {
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

		token := &oauth21proto.UpstreamMCPToken{
			UserId:         "user-1",
			RouteId:        "route-1",
			UpstreamServer: "https://api.example.com",
			RefreshToken:   "old-refresh-token",
			ClientId:       "auto-discovery-cimd-url",
			TokenEndpoint:  tokenSrv.URL,
		}

		_, err := doRefreshUpstreamMCPToken(context.Background(), handler.storage, handler.httpClient, token, "")
		require.NoError(t, err)

		assert.False(t, capturedFormValues.Has("client_secret"),
			"refresh request must NOT include client_secret for auto-discovery clients")
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
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			putPendingUpstreamAuthFunc: func(_ context.Context, pending *oauth21proto.PendingUpstreamAuth) error {
				capturedPending = pending
				return nil
			},
		}

		handler := &UpstreamAuthHandler{
			storage:                 store,
			hosts:                   hosts,
			httpClient:              srv.Client(),
			asMetadataDomainMatcher: allowLocalhost(),
		}

		routeCtx := &extproc.RouteContext{
			RouteID: "route-123",
			UserID:  "user-123",
			IsMCP:   true,
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
func TestReusePendingAuth_ResourceParamConsistency(t *testing.T) {
	t.Parallel()

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
	authURL, err := buildAuthorizationURL(pending.AuthorizationEndpoint, &authorizationURLParams{
		ClientID:            pending.ClientId,
		RedirectURI:         pending.RedirectUri,
		State:               pending.StateId,
		CodeChallenge:       pending.PkceChallenge,
		CodeChallengeMethod: "S256",
		Resource:            resource,
	})
	require.NoError(t, err)

	// Parse the auth URL to extract the resource parameter
	parsedAuthURL, err := url.Parse(authURL)
	require.NoError(t, err)
	authResourceParam := parsedAuthURL.Query().Get("resource")

	// Simulate what ClientOAuthCallback does for the token exchange
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

// TestHandle401_EmptyUserID verifies that handle401 passes through when user ID is empty.
func TestHandle401_EmptyUserID(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Options: &config.Options{
			Policies: []config.Policy{
				{
					Name: "test-mcp-server",
					From: "https://proxy.example.com",
					To:   mustParseWeightedURLs([]string{"https://api.upstream.com"}),
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
		UserID:  "", // empty user ID
		IsMCP:   true,
	}

	action, err := handler.HandleUpstreamResponse(
		context.Background(),
		routeCtx,
		"proxy.example.com",
		"https://api.upstream.com/mcp",
		401,
		"",
	)
	require.NoError(t, err)
	assert.Nil(t, action, "should pass through 401 when user ID is empty")
}

func mustParseWeightedURLs(urls []string) config.WeightedURLs {
	var result config.WeightedURLs
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			panic(fmt.Sprintf("invalid URL %q: %v", raw, err))
		}
		result = append(result, config.WeightedURL{URL: *u})
	}
	return result
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

// TestHandleUpstreamResponse_ExpiresAtHandling verifies token expiry edge cases.
func TestHandleUpstreamResponse_ExpiresAtHandling(t *testing.T) {
	t.Parallel()

	t.Run("nil ExpiresAt treated as not expired", func(t *testing.T) {
		t.Parallel()

		// Token with nil ExpiresAt should be treated as not expired (no refresh attempted)
		token := &oauth21proto.UpstreamMCPToken{
			UserId:         "user-1",
			RouteId:        "route-1",
			UpstreamServer: "https://api.example.com",
			AccessToken:    "still-valid",
			ExpiresAt:      nil, // no expiry info
		}

		var getTokenCalled bool
		fullStore := &autoDiscoveryTestStorage{
			testUpstreamAuthStorage: &testUpstreamAuthStorage{},
			getUpstreamMCPTokenFunc: func(_ context.Context, _, _, _ string) (*oauth21proto.UpstreamMCPToken, error) {
				getTokenCalled = true
				return token, nil
			},
		}

		parsedUpstream, _ := url.Parse("https://api.example.com")
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

		handler := &UpstreamAuthHandler{
			storage: fullStore,
			hosts:   hosts,
		}

		routeCtx := &extproc.RouteContext{
			RouteID: "route-1",
			UserID:  "user-1",
			IsMCP:   true,
		}

		result, err := handler.GetUpstreamToken(context.Background(), routeCtx, "proxy.example.com")
		require.NoError(t, err)
		assert.True(t, getTokenCalled, "should have called GetUpstreamMCPToken")
		assert.Equal(t, "still-valid", result, "should return the non-expired token")
	})

	t.Run("expired token with refresh token attempts refresh", func(t *testing.T) {
		t.Parallel()

		tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token":  "refreshed-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "new-refresh",
			})
		}))
		defer tokenSrv.Close()

		token := &oauth21proto.UpstreamMCPToken{
			UserId:         "user-1",
			RouteId:        "route-1",
			UpstreamServer: "https://api.example.com",
			AccessToken:    "expired",
			RefreshToken:   "old-refresh",
			TokenEndpoint:  tokenSrv.URL,
			ExpiresAt:      timestamppb.New(time.Now().Add(-1 * time.Hour)), // expired
		}

		fullStore := &autoDiscoveryTestStorage{
			testUpstreamAuthStorage: &testUpstreamAuthStorage{},
			getUpstreamMCPTokenFunc: func(_ context.Context, _, _, _ string) (*oauth21proto.UpstreamMCPToken, error) {
				return token, nil
			},
			putUpstreamMCPTokenFunc: func(_ context.Context, _ *oauth21proto.UpstreamMCPToken) error {
				return nil
			},
		}

		parsedUpstream, _ := url.Parse("https://api.example.com")
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

		handler := &UpstreamAuthHandler{
			storage:    fullStore,
			hosts:      hosts,
			httpClient: tokenSrv.Client(),
		}

		routeCtx := &extproc.RouteContext{
			RouteID: "route-1",
			UserID:  "user-1",
			IsMCP:   true,
		}

		result, err := handler.GetUpstreamToken(context.Background(), routeCtx, "proxy.example.com")
		require.NoError(t, err)
		assert.Equal(t, "refreshed-token", result)
	})
}

// TestIsTokenRefreshPermanent verifies that error classification correctly distinguishes
// permanent (4xx) from transient (5xx, network, other) token endpoint errors.
func TestIsTokenRefreshPermanent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		err       error
		permanent bool
	}{
		{"400 Bad Request", &tokenEndpointError{StatusCode: 400, Body: "invalid_grant"}, true},
		{"401 Unauthorized", &tokenEndpointError{StatusCode: 401, Body: "invalid_client"}, true},
		{"403 Forbidden", &tokenEndpointError{StatusCode: 403, Body: "access_denied"}, true},
		{"500 Internal Server Error", &tokenEndpointError{StatusCode: 500, Body: "error"}, false},
		{"502 Bad Gateway", &tokenEndpointError{StatusCode: 502, Body: "error"}, false},
		{"503 Service Unavailable", &tokenEndpointError{StatusCode: 503, Body: "error"}, false},
		{"wrapped 400", fmt.Errorf("token refresh: %w", &tokenEndpointError{StatusCode: 400, Body: "invalid_grant"}), true},
		{"wrapped 500", fmt.Errorf("token refresh: %w", &tokenEndpointError{StatusCode: 500, Body: "error"}), false},
		{"network error", fmt.Errorf("sending token request: %w", fmt.Errorf("connection refused")), false},
		{"nil error", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.permanent, isTokenRefreshPermanent(tt.err))
		})
	}
}

// TestRefreshOrClearToken_ErrorClassification verifies that token refresh distinguishes
// permanent failures (4xx from token endpoint — refresh token revoked) from transient
// failures (5xx, network errors — AS temporarily unavailable).
//
// Permanent: delete cached token, return ("", nil) so next upstream 401 triggers re-auth.
// Transient: preserve cached token, return error so ext_proc returns 502.
func TestRefreshOrClearToken_ErrorClassification(t *testing.T) {
	t.Parallel()

	makeExpiredToken := func(tokenEndpoint string) *oauth21proto.UpstreamMCPToken {
		return &oauth21proto.UpstreamMCPToken{
			UserId:         "user-1",
			RouteId:        "route-1",
			UpstreamServer: "https://api.example.com",
			AccessToken:    "expired-token",
			RefreshToken:   "old-refresh",
			TokenEndpoint:  tokenEndpoint,
			ExpiresAt:      timestamppb.New(time.Now().Add(-1 * time.Hour)),
		}
	}

	makeHandler := func(store HandlerStorage, httpClient *http.Client) *UpstreamAuthHandler {
		parsedUpstream, _ := url.Parse("https://api.example.com")
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
		return &UpstreamAuthHandler{
			storage:    store,
			hosts:      NewHostInfo(cfg, nil),
			httpClient: httpClient,
		}
	}

	routeCtx := &extproc.RouteContext{
		RouteID: "route-1",
		UserID:  "user-1",
		IsMCP:   true,
	}

	t.Run("permanent failure (400) deletes token and returns empty", func(t *testing.T) {
		t.Parallel()

		tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid_grant","error_description":"refresh token expired"}`))
		}))
		defer tokenSrv.Close()

		var tokenDeleted bool
		store := &autoDiscoveryTestStorage{
			testUpstreamAuthStorage: &testUpstreamAuthStorage{},
			getUpstreamMCPTokenFunc: func(_ context.Context, _, _, _ string) (*oauth21proto.UpstreamMCPToken, error) {
				return makeExpiredToken(tokenSrv.URL), nil
			},
			deleteUpstreamMCPTokenFunc: func(_ context.Context, _, _, _ string) error {
				tokenDeleted = true
				return nil
			},
		}

		handler := makeHandler(store, tokenSrv.Client())
		result, err := handler.GetUpstreamToken(context.Background(), routeCtx, "proxy.example.com")
		require.NoError(t, err, "permanent failure should not return an error")
		assert.Empty(t, result, "should return empty token so next 401 triggers re-auth")
		assert.True(t, tokenDeleted, "should delete the cached token (refresh token is invalid)")
	})

	t.Run("permanent failure (401) deletes token and returns empty", func(t *testing.T) {
		t.Parallel()

		tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid_client"}`))
		}))
		defer tokenSrv.Close()

		var tokenDeleted bool
		store := &autoDiscoveryTestStorage{
			testUpstreamAuthStorage: &testUpstreamAuthStorage{},
			getUpstreamMCPTokenFunc: func(_ context.Context, _, _, _ string) (*oauth21proto.UpstreamMCPToken, error) {
				return makeExpiredToken(tokenSrv.URL), nil
			},
			deleteUpstreamMCPTokenFunc: func(_ context.Context, _, _, _ string) error {
				tokenDeleted = true
				return nil
			},
		}

		handler := makeHandler(store, tokenSrv.Client())
		result, err := handler.GetUpstreamToken(context.Background(), routeCtx, "proxy.example.com")
		require.NoError(t, err, "permanent failure should not return an error")
		assert.Empty(t, result)
		assert.True(t, tokenDeleted, "should delete the cached token (client rejected)")
	})

	t.Run("transient failure (500) preserves token and returns error", func(t *testing.T) {
		t.Parallel()

		tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal server error"))
		}))
		defer tokenSrv.Close()

		var tokenDeleted bool
		store := &autoDiscoveryTestStorage{
			testUpstreamAuthStorage: &testUpstreamAuthStorage{},
			getUpstreamMCPTokenFunc: func(_ context.Context, _, _, _ string) (*oauth21proto.UpstreamMCPToken, error) {
				return makeExpiredToken(tokenSrv.URL), nil
			},
			deleteUpstreamMCPTokenFunc: func(_ context.Context, _, _, _ string) error {
				tokenDeleted = true
				return nil
			},
		}

		handler := makeHandler(store, tokenSrv.Client())
		result, err := handler.GetUpstreamToken(context.Background(), routeCtx, "proxy.example.com")
		require.Error(t, err, "transient failure should return an error (triggers 502)")
		assert.Empty(t, result)
		assert.False(t, tokenDeleted, "should NOT delete the cached token (AS might recover)")
		assert.Contains(t, err.Error(), "refreshing upstream token")
	})

	t.Run("transient failure (503) preserves token and returns error", func(t *testing.T) {
		t.Parallel()

		tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("service unavailable"))
		}))
		defer tokenSrv.Close()

		var tokenDeleted bool
		store := &autoDiscoveryTestStorage{
			testUpstreamAuthStorage: &testUpstreamAuthStorage{},
			getUpstreamMCPTokenFunc: func(_ context.Context, _, _, _ string) (*oauth21proto.UpstreamMCPToken, error) {
				return makeExpiredToken(tokenSrv.URL), nil
			},
			deleteUpstreamMCPTokenFunc: func(_ context.Context, _, _, _ string) error {
				tokenDeleted = true
				return nil
			},
		}

		handler := makeHandler(store, tokenSrv.Client())
		result, err := handler.GetUpstreamToken(context.Background(), routeCtx, "proxy.example.com")
		require.Error(t, err, "transient failure should return an error")
		assert.Empty(t, result)
		assert.False(t, tokenDeleted, "should NOT delete the cached token")
	})

	t.Run("network error preserves token and returns error", func(t *testing.T) {
		t.Parallel()

		store := &autoDiscoveryTestStorage{
			testUpstreamAuthStorage: &testUpstreamAuthStorage{},
			getUpstreamMCPTokenFunc: func(_ context.Context, _, _, _ string) (*oauth21proto.UpstreamMCPToken, error) {
				// Point to a non-routable address to trigger a network error
				return makeExpiredToken("http://192.0.2.1:1/token"), nil
			},
			deleteUpstreamMCPTokenFunc: func(_ context.Context, _, _, _ string) error {
				t.Error("should NOT delete token on network error")
				return nil
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		handler := makeHandler(store, &http.Client{Timeout: 1 * time.Second})
		result, err := handler.GetUpstreamToken(ctx, routeCtx, "proxy.example.com")
		require.Error(t, err, "network error should return an error")
		assert.Empty(t, result)
		assert.Contains(t, err.Error(), "refreshing upstream token")
	})
}

// autoDiscoveryTestStorage extends testUpstreamAuthStorage with additional methods
// needed for the auto-discovery token path.
type autoDiscoveryTestStorage struct {
	*testUpstreamAuthStorage
	getUpstreamMCPTokenFunc    func(ctx context.Context, userID, routeID, upstreamServer string) (*oauth21proto.UpstreamMCPToken, error)
	deleteUpstreamMCPTokenFunc func(ctx context.Context, userID, routeID, upstreamServer string) error
	putUpstreamMCPTokenFunc    func(ctx context.Context, token *oauth21proto.UpstreamMCPToken) error
}

func (s *autoDiscoveryTestStorage) GetUpstreamMCPToken(ctx context.Context, userID, routeID, upstreamServer string) (*oauth21proto.UpstreamMCPToken, error) {
	if s.getUpstreamMCPTokenFunc != nil {
		return s.getUpstreamMCPTokenFunc(ctx, userID, routeID, upstreamServer)
	}
	return nil, status.Error(codes.NotFound, "not found")
}

func (s *autoDiscoveryTestStorage) DeleteUpstreamMCPToken(ctx context.Context, userID, routeID, upstreamServer string) error {
	if s.deleteUpstreamMCPTokenFunc != nil {
		return s.deleteUpstreamMCPTokenFunc(ctx, userID, routeID, upstreamServer)
	}
	return nil
}

func (s *autoDiscoveryTestStorage) PutUpstreamMCPToken(ctx context.Context, token *oauth21proto.UpstreamMCPToken) error {
	if s.putUpstreamMCPTokenFunc != nil {
		return s.putUpstreamMCPTokenFunc(ctx, token)
	}
	return nil
}
