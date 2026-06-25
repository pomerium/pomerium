package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/mcp/extproc"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
)

// TestHandleUpstreamResponse_ConfiguredUpstreamBasePath reproduces the production failure
// observed against https://notion-mcp.corp.pomerium.com (route "to" = https://mcp.notion.com/mcp).
//
// In the reactive ext_proc path, originalURL is reconstructed from the upstream host plus the
// *downstream* request path. Envoy applies the route's upstream path rewrite only AFTER ext_proc
// reads the request headers, so when the MCP client connects to the route root ("/"), the
// configured "/mcp" base path is dropped and originalURL becomes "https://host/" (origin only).
//
// Notion advertises its Protected Resource Metadata resource as the "/mcp" subpath
// ("https://mcp.notion.com/mcp"). checkResourceAllowed requires the PRM resource path to be a
// prefix of the resource URL path, so validating "/mcp" against the path-stripped "/" fails with:
//
//	upstream OAuth setup: running discovery: PRM resource "https://mcp.notion.com/mcp"
//	does not match upstream server "https://mcp.notion.com/"
//
// and the entire re-auth flow aborts (no action, error returned) — the user is stuck in a 401 loop.
//
// The proactive /.pomerium/mcp/authorize path (handler_connect.go) does not have this bug because
// it validates against the configured info.UpstreamURL (which retains "/mcp"). This test pins the
// reactive path to the same correct behavior.
func TestHandleUpstreamResponse_ConfiguredUpstreamBasePath(t *testing.T) {
	t.Parallel()

	var upstreamURL string
	upstreamSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource/mcp",
			"/.well-known/oauth-protected-resource":
			// Concrete Notion behavior: the PRM resource is the "/mcp" subpath.
			_ = json.NewEncoder(w).Encode(ProtectedResourceMetadata{
				Resource:             upstreamURL + "/mcp",
				AuthorizationServers: []string{upstreamURL + "/oauth"},
			})
		case "/.well-known/oauth-authorization-server/oauth":
			_ = json.NewEncoder(w).Encode(AuthorizationServerMetadata{
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

	// The route's upstream "to" carries the "/mcp" base path (Notion's pattern).
	parsedUpstream, err := url.Parse(upstreamURL + "/mcp")
	require.NoError(t, err)

	cfg := config.New(&config.Options{
		Policies: []config.Policy{
			{
				Name: "test-mcp-server",
				From: "https://proxy.example.com",
				To:   config.WeightedURLs{{URL: *parsedUpstream}},
				MCP:  &config.MCP{Server: &config.MCPServer{}},
			},
		},
	})
	hosts := NewHostInfo(cfg, nil)

	// Sanity: the configured upstream URL retains the "/mcp" base path (matches prod log
	// "upstream_server":"https://mcp.notion.com/mcp").
	info, ok := hosts.GetServerHostInfo("proxy.example.com")
	require.True(t, ok)
	require.Equal(t, upstreamURL+"/mcp", info.UpstreamURL,
		"configured upstream URL must include the /mcp base path")

	var capturedPending *oauth21proto.PendingUpstreamAuth
	store := &testUpstreamAuthStorage{
		putPendingUpstreamAuthFunc: func(_ context.Context, pending *oauth21proto.PendingUpstreamAuth) error {
			capturedPending = pending
			return nil
		},
	}

	handler := NewUpstreamAuthHandler(store, hosts, upstreamSrv.Client(), allowLocalhost())

	routeCtx := &extproc.RouteContext{
		RouteID: "route-123",
		UserID:  "user-123",
		IsMCP:   true,
	}

	// The MCP client connects to the route root, so ext_proc reconstructs originalURL as the
	// upstream host + the downstream request path "/", WITHOUT the configured "/mcp" base path.
	action, err := handler.HandleUpstreamResponse(
		context.Background(),
		routeCtx,
		"proxy.example.com", // downstream host
		upstreamURL+"/",     // originalURL: origin only — the "/mcp" base path is lost
		401,                 // upstream returned 401
		"",                  // no WWW-Authenticate (discovery falls back to well-known)
	)

	require.NoError(t, err,
		"re-auth setup must succeed: the upstream advertises its PRM resource as the /mcp "+
			"subpath and the route's upstream is configured with /mcp")
	require.NotNil(t, action, "should return a re-auth challenge action, not abort discovery")

	require.NotNil(t, capturedPending, "a pending upstream auth must be stored")
	assert.Equal(t, upstreamURL+"/mcp", capturedPending.UpstreamServer,
		"pending auth must store the configured upstream URL (with /mcp) for token storage keys")
	assert.Equal(t, upstreamURL+"/mcp", capturedPending.ResourceParam,
		"RFC 8707 resource indicator must be the upstream's advertised PRM resource (https://host/mcp)")
}
