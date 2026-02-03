package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/controlplane"
	"github.com/pomerium/pomerium/internal/mcp/extproc"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	pomerium "github.com/pomerium/pomerium/pkg/cmd/pomerium"
)

func TestExtProcMCPRouteInvocation(t *testing.T) {
	// Track ext_proc callback invocations using channel for synchronization
	callbackInvoked := make(chan *extproc.RouteContext, 10)

	extProcCallback := func(_ context.Context, routeCtx *extproc.RouteContext, _ *ext_proc_v3.HttpHeaders) {
		callbackInvoked <- routeCtx
	}

	env := testenv.New(t)

	// Enable MCP runtime flag and set ext_proc callback
	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.RuntimeFlags == nil {
			cfg.Options.RuntimeFlags = make(config.RuntimeFlags)
		}
		cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = true
		cfg.Options.MCPAllowedClientIDDomains = []string{"*.localhost.pomerium.io"}
	}))

	// Add ext_proc callback through controlplane options
	env.AddOption(pomerium.WithControlPlaneServerOptions(
		controlplane.WithExtProcCallback(extProcCallback),
	))

	// Set up IDP
	idp := scenarios.NewIDP([]*scenarios.User{
		{Email: "user@example.com"},
	})
	env.Add(idp)

	// Create MCP server upstream
	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "test-server",
		Version: "1.0.0",
	}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "hello",
		Description: "Returns a greeting",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "Hello from MCP Server!"},
			},
		}, nil, nil
	})

	serverUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("MCP Server"))
	serverHandler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return mcpServer
	}, nil)
	serverUpstream.Handle("/", serverHandler.ServeHTTP)

	mcpRoute := serverUpstream.Route().
		From(env.SubdomainURL("mcp-ext-proc-test")).
		Policy(func(p *config.Policy) {
			p.AllowedDomains = []string{"example.com"}
			p.MCP = &config.MCP{
				Server: &config.MCPServer{},
			}
		})
	env.AddUpstream(serverUpstream)

	// Create client route for token acquisition
	clientUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("MCP Client Proxy"))
	clientUpstream.Handle("/token", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "missing or invalid authorization header", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, strings.TrimPrefix(auth, "Bearer "))
	})
	clientRoute := clientUpstream.Route().
		From(env.SubdomainURL("mcp-client-ext-proc")).
		PPL(`
- allow:
    and:
      - domain:
          is: example.com
`).
		Policy(func(p *config.Policy) {
			p.MCP = &config.MCP{
				Client: &config.MCPClient{},
			}
		})
	env.AddUpstream(clientUpstream)

	// Also create a non-MCP route to verify ext_proc is NOT invoked for it
	regularUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("Regular Server"))
	regularUpstream.Handle("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	regularRoute := regularUpstream.Route().
		From(env.SubdomainURL("regular-ext-proc")).
		Policy(func(p *config.Policy) {
			p.AllowedDomains = []string{"example.com"}
		})
	env.AddUpstream(regularUpstream)

	env.Start()
	snippets.WaitStartupComplete(env)

	getToken := func(email string) string {
		resp, err := clientUpstream.Get(clientRoute,
			upstreams.Path("/token"),
			upstreams.AuthenticateAs(email),
			upstreams.ClientHook(func(c *http.Client) *http.Client {
				c.Jar, _ = cookiejar.New(nil)
				return c
			}),
		)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		tokenBytes, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return string(tokenBytes)
	}

	// Drain any callbacks from setup/warmup
	drainCallbacks := func() {
		for {
			select {
			case <-callbackInvoked:
			default:
				return
			}
		}
	}

	t.Run("ext_proc invoked for MCP route", func(t *testing.T) {
		drainCallbacks()

		userToken := getToken("user@example.com")

		// Make a request to the MCP server
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()

		session, err := connectMCP(ctx, env, mcpRoute.URL().Value(), userToken)
		require.NoError(t, err)
		defer session.Close()

		// Call a tool to trigger the ext_proc handler
		result, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name: "hello",
		})
		require.NoError(t, err)
		require.NotEmpty(t, result.Content)

		// ext_proc callback should have been invoked during the request/response cycle.
		// Use a short timeout in case the callback is processed asynchronously.
		select {
		case routeCtx := <-callbackInvoked:
			require.NotNil(t, routeCtx, "route context should not be nil")
			assert.True(t, routeCtx.IsMCP, "route context should indicate MCP route")
			assert.NotEmpty(t, routeCtx.RouteID, "route context should have route ID")
		case <-time.After(5 * time.Second):
			t.Fatal("ext_proc callback was not invoked for MCP route")
		}
	})

	t.Run("ext_proc not invoked for non-MCP route", func(t *testing.T) {
		drainCallbacks()

		// Make a request to the regular (non-MCP) route
		resp, err := regularUpstream.Get(regularRoute,
			upstreams.Path("/"),
			upstreams.AuthenticateAs("user@example.com"),
		)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// ext_proc should NOT be invoked for non-MCP routes.
		// Use a short timeout to verify no callback is received.
		select {
		case <-callbackInvoked:
			t.Fatal("ext_proc callback should not be invoked for non-MCP routes")
		case <-time.After(100 * time.Millisecond):
			// Expected: no callback invoked
		}
	})
}
