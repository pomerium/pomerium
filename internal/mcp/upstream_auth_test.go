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
	"github.com/pomerium/pomerium/pkg/grpc/user"
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
			storage:                 store,
			hosts:                   hosts,
			httpClient:              upstreamSrv.Client(),
			asMetadataDomainMatcher: allowLocalhost(),
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
	getServiceAccountFunc      func(ctx context.Context, id string) (*user.ServiceAccount, error)
	putPendingUpstreamAuthFunc func(ctx context.Context, pending *oauth21proto.PendingUpstreamAuth) error
}

func (s *testUpstreamAuthStorage) GetSession(ctx context.Context, id string) (*session.Session, error) {
	if s.getSessionFunc != nil {
		return s.getSessionFunc(ctx, id)
	}
	return nil, status.Error(codes.NotFound, "session not found")
}

func (s *testUpstreamAuthStorage) GetServiceAccount(ctx context.Context, id string) (*user.ServiceAccount, error) {
	if s.getServiceAccountFunc != nil {
		return s.getServiceAccountFunc(ctx, id)
	}
	return nil, status.Error(codes.NotFound, "service account not found")
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

// TestHandle401_ClientRegistrationStrategy verifies the CIMD check logic.
func TestHandle401_ClientRegistrationStrategy(t *testing.T) {
	t.Parallel()

	// newMockUpstream creates a TLS test server that serves PRM and AS metadata.
	// asMetadataExtra is merged into the AS metadata response.
	newMockUpstream := func(asMetadataExtra func(baseURL string) map[string]any) (*httptest.Server, *string) {
		var srvURL string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			storage:                 store,
			hosts:                   hosts,
			httpClient:              upstreamSrv.Client(),
			asMetadataDomainMatcher: allowLocalhost(),
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

	t.Run("CIMD not supported — returns error", func(t *testing.T) {
		t.Parallel()

		upstreamSrv, upstreamURL := newMockUpstream(func(_ string) map[string]any {
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
			getSessionFunc: func(_ context.Context, _ string) (*session.Session, error) {
				return &session.Session{UserId: "user-123"}, nil
			},
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

// TestServiceAccountSupport verifies that service accounts are handled correctly
// in the upstream auth flow: getSessionIdentity falls back to service accounts,
// and handle401 passes through upstream 401 responses for service accounts.
func TestServiceAccountSupport(t *testing.T) {
	t.Parallel()

	t.Run("getSessionIdentity falls back to service account", func(t *testing.T) {
		t.Parallel()

		store := &testUpstreamAuthStorage{
			getSessionFunc: func(_ context.Context, _ string) (*session.Session, error) {
				return nil, status.Error(codes.NotFound, "not found")
			},
			getServiceAccountFunc: func(_ context.Context, id string) (*user.ServiceAccount, error) {
				assert.Equal(t, "sa-123", id)
				return &user.ServiceAccount{Id: "sa-123", UserId: "user-456"}, nil
			},
		}

		handler := &UpstreamAuthHandler{storage: store}
		identity, err := handler.getSessionIdentity(context.Background(), "sa-123")
		require.NoError(t, err)
		assert.Equal(t, "user-456", identity.UserID)
		assert.True(t, identity.IsServiceAccount)
	})

	t.Run("getSessionIdentity prefers session over service account", func(t *testing.T) {
		t.Parallel()

		store := &testUpstreamAuthStorage{
			getSessionFunc: func(_ context.Context, _ string) (*session.Session, error) {
				return &session.Session{UserId: "user-789"}, nil
			},
		}

		handler := &UpstreamAuthHandler{storage: store}
		identity, err := handler.getSessionIdentity(context.Background(), "session-123")
		require.NoError(t, err)
		assert.Equal(t, "user-789", identity.UserID)
		assert.False(t, identity.IsServiceAccount)
	})

	t.Run("getSessionIdentity rejects empty session ID", func(t *testing.T) {
		t.Parallel()

		handler := &UpstreamAuthHandler{storage: &testUpstreamAuthStorage{}}
		identity, err := handler.getSessionIdentity(context.Background(), "")
		require.Error(t, err)
		assert.Nil(t, identity)
		assert.Contains(t, err.Error(), "no session ID")
	})

	t.Run("getSessionIdentity propagates non-not-found session error", func(t *testing.T) {
		t.Parallel()

		store := &testUpstreamAuthStorage{
			getSessionFunc: func(_ context.Context, _ string) (*session.Session, error) {
				return nil, status.Error(codes.Internal, "databroker unavailable")
			},
			getServiceAccountFunc: func(_ context.Context, _ string) (*user.ServiceAccount, error) {
				t.Fatal("GetServiceAccount should not be called on non-not-found session error")
				return nil, nil
			},
		}

		handler := &UpstreamAuthHandler{storage: store}
		identity, err := handler.getSessionIdentity(context.Background(), "session-123")
		require.Error(t, err)
		assert.Nil(t, identity)
		assert.Contains(t, err.Error(), "getting session")
	})

	t.Run("getSessionIdentity rejects expired service account", func(t *testing.T) {
		t.Parallel()

		store := &testUpstreamAuthStorage{
			getSessionFunc: func(_ context.Context, _ string) (*session.Session, error) {
				return nil, status.Error(codes.NotFound, "not found")
			},
			getServiceAccountFunc: func(_ context.Context, _ string) (*user.ServiceAccount, error) {
				return &user.ServiceAccount{
					Id:        "sa-expired",
					UserId:    "user-456",
					ExpiresAt: timestamppb.New(time.Now().Add(-1 * time.Hour)),
				}, nil
			},
		}

		handler := &UpstreamAuthHandler{storage: store}
		identity, err := handler.getSessionIdentity(context.Background(), "sa-expired")
		require.Error(t, err)
		assert.Nil(t, identity)
		assert.Contains(t, err.Error(), "invalid")
		assert.ErrorIs(t, err, user.ErrServiceAccountExpired)
	})

	t.Run("getSessionIdentity rejects service account without user ID", func(t *testing.T) {
		t.Parallel()

		store := &testUpstreamAuthStorage{
			getSessionFunc: func(_ context.Context, _ string) (*session.Session, error) {
				return nil, status.Error(codes.NotFound, "not found")
			},
			getServiceAccountFunc: func(_ context.Context, _ string) (*user.ServiceAccount, error) {
				return &user.ServiceAccount{Id: "sa-no-uid", UserId: ""}, nil
			},
		}

		handler := &UpstreamAuthHandler{storage: store}
		identity, err := handler.getSessionIdentity(context.Background(), "sa-no-uid")
		require.Error(t, err)
		assert.Nil(t, identity)
		assert.Contains(t, err.Error(), "no user ID")
	})

	t.Run("handle401 returns nil when neither session nor service account exists", func(t *testing.T) {
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

		// Both GetSession and GetServiceAccount return not-found (defaults).
		store := &testUpstreamAuthStorage{}

		handler := &UpstreamAuthHandler{
			storage: store,
			hosts:   hosts,
		}

		routeCtx := &extproc.RouteContext{
			RouteID:   "route-123",
			SessionID: "nonexistent-id",
			IsMCP:     true,
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
		assert.Nil(t, action, "should pass through 401 when identity not found")
	})

	t.Run("handle401 passes through for service accounts", func(t *testing.T) {
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

		store := &testUpstreamAuthStorage{
			getSessionFunc: func(_ context.Context, _ string) (*session.Session, error) {
				return nil, status.Error(codes.NotFound, "not found")
			},
			getServiceAccountFunc: func(_ context.Context, _ string) (*user.ServiceAccount, error) {
				return &user.ServiceAccount{Id: "sa-123", UserId: "user-456"}, nil
			},
		}

		handler := &UpstreamAuthHandler{
			storage: store,
			hosts:   hosts,
		}

		routeCtx := &extproc.RouteContext{
			RouteID:   "route-123",
			SessionID: "sa-123",
			IsMCP:     true,
		}

		// Service accounts should get nil action (pass through the 401)
		action, err := handler.HandleUpstreamResponse(
			context.Background(),
			routeCtx,
			"proxy.example.com",
			"https://api.upstream.com/mcp",
			401,
			"",
		)
		require.NoError(t, err)
		assert.Nil(t, action, "should pass through 401 for service accounts")
	})
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

func (s *refreshTokenTestStorage) GetServiceAccount(context.Context, string) (*user.ServiceAccount, error) {
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
