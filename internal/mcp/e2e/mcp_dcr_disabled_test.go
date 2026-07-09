package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	mcphandler "github.com/pomerium/pomerium/internal/mcp"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/pkg/endpoints"
)

// TestMCPDynamicClientRegistrationDisabled verifies that when the
// mcp_dynamic_client_registration runtime flag is off (the default), the
// downstream /register endpoint refuses requests and the registration_endpoint
// is not advertised, while CIMD support remains advertised.
func TestMCPDynamicClientRegistrationDisabled(t *testing.T) {
	env := testenv.New(t)

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		enableMCP(cfg, false)
		cfg.Options.MCPAllowedClientIDDomains = []string{"*.localhost.pomerium.io"}
	}))

	idp := scenarios.NewIDP([]*scenarios.User{
		{Email: "user@example.com"},
	})
	env.Add(idp)

	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "test-server",
		Version: "1.0.0",
	}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "ping",
		Description: "Returns pong",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "pong"}},
		}, nil, nil
	})

	serverUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("MCP Server"))
	serverHandler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return mcpServer
	}, nil)
	serverUpstream.Handle("/", serverHandler.ServeHTTP)

	serverRoute := serverUpstream.Route().
		From(env.SubdomainURL("mcp-dcr-disabled")).
		Policy(func(p *config.Policy) {
			p.AllowedDomains = []string{"example.com"}
			p.MCP = &config.MCP{Server: &config.MCPServer{}}
		})
	env.AddUpstream(serverUpstream)

	env.Start()
	snippets.WaitStartupComplete(env)

	ctx := env.Context()
	parsedURL, err := url.Parse(serverRoute.URL().Value())
	require.NoError(t, err)

	newClient := func() *http.Client {
		c := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
		c.Jar, _ = cookiejar.New(nil)
		c.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		}
		return c
	}

	t.Run("metadata omits registration_endpoint but keeps CIMD", func(t *testing.T) {
		asMetadataURL := "https://" + parsedURL.Host + mcphandler.WellKnownAuthorizationServerEndpoint
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, asMetadataURL, nil)
		require.NoError(t, err)
		resp, err := newClient().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var metadata map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&metadata))

		_, hasRegistration := metadata["registration_endpoint"]
		assert.False(t, hasRegistration, "registration_endpoint must not be advertised when DCR disabled")

		supported, _ := metadata["client_id_metadata_document_supported"].(bool)
		assert.True(t, supported, "client_id_metadata_document_supported should remain true")
	})

	t.Run("register endpoint returns 403", func(t *testing.T) {
		registerURL := "https://" + parsedURL.Host + endpoints.PathPomeriumMCP + "/register"
		clientMetadata := map[string]any{
			"redirect_uris":              []string{"http://localhost:8080/callback"},
			"client_name":                "Should Be Rejected",
			"token_endpoint_auth_method": "none",
			"grant_types":                []string{"authorization_code"},
			"response_types":             []string{"code"},
		}
		body, err := json.Marshal(clientMetadata)
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, registerURL, strings.NewReader(string(body)))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := newClient().Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusForbidden, resp.StatusCode, "registration must be refused when DCR disabled")

		var errResp map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&errResp))
		assert.Equal(t, "access_denied", errResp["error"])
	})
}
