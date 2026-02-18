package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/pkg/endpoints"
)

// serverListResponse is the JSON response returned by the
// GET /mcp/routes and POST /mcp/routes/disconnect endpoints.
type serverListResponse struct {
	Servers []serverInfoResponse `json:"servers"`
}

type serverInfoResponse struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	LogoURL     string `json:"logo_url,omitempty"`
	URL         string `json:"url"`
	Connected   bool   `json:"connected"`
	NeedsOauth  bool   `json:"needs_oauth"`
}

// TestMCPClientRoutes tests the MCP client route management endpoints:
//   - GET  /.pomerium/mcp/routes             (ListRoutes)
//   - GET  /.pomerium/mcp/connect            (ConnectGet)
//   - POST /.pomerium/mcp/routes/disconnect  (DisconnectRoutes)
func TestMCPClientRoutes(t *testing.T) {
	env := testenv.New(t)

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.RuntimeFlags == nil {
			cfg.Options.RuntimeFlags = make(config.RuntimeFlags)
		}
		cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = true
		cfg.Options.MCPAllowedClientIDDomains = []string{"*.localhost.pomerium.io"}
	}))

	idp := scenarios.NewIDP([]*scenarios.User{
		{Email: "user@example.com"},
	})
	env.Add(idp)

	// Create an MCP server upstream with a simple echo tool.
	mcpServer := sdkmcp.NewServer(&sdkmcp.Implementation{
		Name:    "test-server",
		Version: "1.0.0",
	}, nil)
	sdkmcp.AddTool(mcpServer, &sdkmcp.Tool{
		Name:        "echo",
		Description: "Echoes input",
	}, func(_ context.Context, _ *sdkmcp.CallToolRequest, _ any) (*sdkmcp.CallToolResult, any, error) {
		return &sdkmcp.CallToolResult{
			Content: []sdkmcp.Content{
				&sdkmcp.TextContent{Text: "echo"},
			},
		}, nil, nil
	})

	serverUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("MCP Test Server"))
	serverHandler := sdkmcp.NewStreamableHTTPHandler(func(_ *http.Request) *sdkmcp.Server {
		return mcpServer
	}, nil)
	serverUpstream.Handle("/", serverHandler.ServeHTTP)

	server1Route := serverUpstream.Route().
		From(env.SubdomainURL("mcp-routes-s1")).
		Policy(func(p *config.Policy) {
			p.AllowedDomains = []string{"example.com"}
			p.Name = "Server One"
			p.Description = "First test server"
			p.MCP = &config.MCP{
				Server: &config.MCPServer{},
			}
		})
	server2Route := serverUpstream.Route().
		From(env.SubdomainURL("mcp-routes-s2")).
		Policy(func(p *config.Policy) {
			p.AllowedDomains = []string{"example.com"}
			p.Name = "Server Two"
			p.MCP = &config.MCP{
				Server: &config.MCPServer{},
			}
		})
	env.AddUpstream(serverUpstream)

	// Create an MCP client route (needed for connect redirect_url validation).
	clientUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("MCP Test Client"))
	clientRoute := clientUpstream.Route().
		From(env.SubdomainURL("mcp-routes-client")).
		Policy(func(p *config.Policy) {
			p.AllowedDomains = []string{"example.com"}
			p.MCP = &config.MCP{
				Client: &config.MCPClient{},
			}
		})
	env.AddUpstream(clientUpstream)

	env.Start()
	snippets.WaitStartupComplete(env)

	ctx := env.Context()

	// authenticatedClient returns an HTTP client with an active Pomerium session
	// for the given route. The client has cookies set from going through the IDP
	// login flow and does NOT follow redirects automatically.
	authenticatedClient := func(t *testing.T, route testenv.Route) *http.Client {
		t.Helper()
		client := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
		client.Jar, _ = cookiejar.New(nil)

		// Authenticate by hitting /.pomerium/mcp/routes which is in the
		// internalPathsNeedingLogin set and will redirect unauthenticated
		// browser requests to the IDP.
		authReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
			route.URL().Value()+endpoints.PathPomeriumMCPRoutes, nil)
		require.NoError(t, err)
		resp, err := upstreams.AuthenticateFlow(ctx, client, authReq, "user@example.com", true)
		require.NoError(t, err)
		resp.Body.Close()

		// Disable automatic redirect following for subsequent requests so
		// callers can inspect redirect responses (e.g. ConnectGet).
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
		return client
	}

	// ---- ListRoutes ----

	t.Run("list routes returns configured servers", func(t *testing.T) {
		client := authenticatedClient(t, server1Route)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			server1Route.URL().Value()+endpoints.PathPomeriumMCPRoutes, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var result serverListResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))

		// Should include both MCP server routes (but not the client route).
		require.GreaterOrEqual(t, len(result.Servers), 2,
			"expected at least 2 MCP server routes in the response")

		// Collect the returned route URLs for matching.
		routeURLs := make(map[string]serverInfoResponse)
		for _, s := range result.Servers {
			routeURLs[s.URL] = s
		}

		s1URL := server1Route.URL().Value()
		s2URL := server2Route.URL().Value()

		s1, ok := routeURLs[s1URL]
		require.True(t, ok, "server1 route URL %q should be in response", s1URL)
		assert.Equal(t, "Server One", s1.Name)
		assert.Equal(t, "First test server", s1.Description)
		assert.True(t, s1.NeedsOauth, "auto-discovery route should report needs_oauth=true")
		assert.False(t, s1.Connected, "route should be disconnected initially")

		s2, ok := routeURLs[s2URL]
		require.True(t, ok, "server2 route URL %q should be in response", s2URL)
		assert.Equal(t, "Server Two", s2.Name)
		assert.True(t, s2.NeedsOauth)
		assert.False(t, s2.Connected)

		// Client route should NOT appear in the server list.
		clientURL := clientRoute.URL().Value()
		_, hasClient := routeURLs[clientURL]
		assert.False(t, hasClient, "client route should not appear in server list")
	})

	t.Run("list routes has no-cache headers", func(t *testing.T) {
		client := authenticatedClient(t, server1Route)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			server1Route.URL().Value()+endpoints.PathPomeriumMCPRoutes, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))
		assert.Contains(t, resp.Header.Get("Cache-Control"), "no-store")
	})

	// ---- ConnectGet ----

	t.Run("connect missing redirect_url returns 400", func(t *testing.T) {
		client := authenticatedClient(t, server1Route)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			server1Route.URL().Value()+endpoints.PathPomeriumMCPConnect, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("connect non-https redirect_url returns 400", func(t *testing.T) {
		client := authenticatedClient(t, server1Route)
		connectURL := server1Route.URL().Value() + endpoints.PathPomeriumMCPConnect +
			"?redirect_url=" + url.QueryEscape("http://mcp-routes-client.localhost.pomerium.io/callback")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, connectURL, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("connect redirect_url to non-client host returns 400", func(t *testing.T) {
		client := authenticatedClient(t, server1Route)
		// Use the server route URL as redirect_url — it's NOT an MCP client.
		connectURL := server1Route.URL().Value() + endpoints.PathPomeriumMCPConnect +
			"?redirect_url=" + url.QueryEscape(server1Route.URL().Value()+"/callback")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, connectURL, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("connect auto-discovery route without PRM redirects to redirect_url", func(t *testing.T) {
		client := authenticatedClient(t, server1Route)
		redirectTarget := clientRoute.URL().Value() + "/after-connect"
		connectURL := server1Route.URL().Value() + endpoints.PathPomeriumMCPConnect +
			"?redirect_url=" + url.QueryEscape(redirectTarget)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, connectURL, nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// The upstream test server has no PRM, so the connect handler
		// should fall through and redirect to the provided redirect_url.
		assert.Equal(t, http.StatusFound, resp.StatusCode)
		location := resp.Header.Get("Location")
		assert.Equal(t, redirectTarget, location,
			"expected redirect to the provided redirect_url when upstream has no PRM")
	})

	// ---- DisconnectRoutes ----

	t.Run("disconnect empty routes returns 400", func(t *testing.T) {
		client := authenticatedClient(t, server1Route)
		body := strings.NewReader(`{"routes":[]}`)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			server1Route.URL().Value()+endpoints.PathPomeriumMCPRoutes+"/disconnect", body)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("disconnect invalid body returns 400", func(t *testing.T) {
		client := authenticatedClient(t, server1Route)
		body := strings.NewReader(`not json`)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			server1Route.URL().Value()+endpoints.PathPomeriumMCPRoutes+"/disconnect", body)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("disconnect returns updated server list", func(t *testing.T) {
		client := authenticatedClient(t, server1Route)
		disconnectBody := map[string]any{
			"routes": []string{
				server1Route.URL().Value(),
				server2Route.URL().Value(),
			},
		}
		bodyBytes, err := json.Marshal(disconnectBody)
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			server1Route.URL().Value()+endpoints.PathPomeriumMCPRoutes+"/disconnect",
			strings.NewReader(string(bodyBytes)))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var result serverListResponse
		bodyData, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(bodyData, &result))

		// Response should include the full server list.
		require.GreaterOrEqual(t, len(result.Servers), 2)

		// All servers should be disconnected.
		for _, s := range result.Servers {
			assert.False(t, s.Connected,
				"server %q should be disconnected after disconnect call", s.URL)
		}
	})
}
