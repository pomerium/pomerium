package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
)

func TestMCPIntegration(t *testing.T) {
	env := testenv.New(t)

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.RuntimeFlags == nil {
			cfg.Options.RuntimeFlags = make(config.RuntimeFlags)
		}
		cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = true
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
		Name:        "hello",
		Description: "Returns a greeting",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "Hello from MCP Server!"},
			},
		}, nil, nil
	})
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "echo",
		Description: "Echoes the input",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"message": map[string]any{"type": "string"},
			},
		},
	}, func(_ context.Context, _ *mcp.CallToolRequest, args any) (*mcp.CallToolResult, any, error) {
		m := args.(map[string]any)
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: m["message"].(string)},
			},
		}, nil, nil
	})

	serverUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("MCP Server"))
	serverHandler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return mcpServer
	}, nil)
	serverUpstream.Handle("/", serverHandler.ServeHTTP)

	serverRoute := serverUpstream.Route().
		From(env.SubdomainURL("mcp-server")).
		Policy(func(p *config.Policy) {
			p.AllowedDomains = []string{"example.com"}
			p.MCP = &config.MCP{
				Server: &config.MCPServer{},
			}
		})

	echoOnlyRoute := serverUpstream.Route().
		From(env.SubdomainURL("mcp-echo-only")).
		PPL(`
- allow:
    and:
      - email:
          is: user@example.com
- deny:
    or:
      - mcp_tool:
          not: echo
`).
		Policy(func(p *config.Policy) {
			p.MCP = &config.MCP{
				Server: &config.MCPServer{},
			}
		})

	otherUserRoute := serverUpstream.Route().
		From(env.SubdomainURL("mcp-other-user")).
		PPL(`
- allow:
    and:
      - email:
          is: user@other.com
`).
		Policy(func(p *config.Policy) {
			p.MCP = &config.MCP{
				Server: &config.MCPServer{},
			}
		})
	env.AddUpstream(serverUpstream)

	// the mcp go-sdk does not currently provide functions to perform e2e token acquisition flow
	// we just use the pomerium mcp client feature to acquire a token and use it to perform calls to the mcp server
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
		From(env.SubdomainURL("mcp-client")).
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

	env.Start()

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

	userToken := getToken("user@example.com")

	tests := []struct {
		name      string
		endpoint  string
		tool      string
		arguments map[string]any
		wantErr   bool
	}{
		{
			name:     "general access hello",
			endpoint: serverRoute.URL().Value(),
			tool:     "hello",
		},
		{
			name:      "general access echo",
			endpoint:  serverRoute.URL().Value(),
			tool:      "echo",
			arguments: map[string]any{"message": "hi"},
		},
		{
			name:      "echo only route echo success",
			endpoint:  echoOnlyRoute.URL().Value(),
			tool:      "echo",
			arguments: map[string]any{"message": "hi"},
		},
		{
			name:     "echo only route hello failure",
			endpoint: echoOnlyRoute.URL().Value(),
			tool:     "hello",
			wantErr:  true,
		},
		{
			name:     "other user route failure",
			endpoint: otherUserRoute.URL().Value(),
			tool:     "hello",
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			session, err := connectMCP(ctx, env, tc.endpoint, userToken)
			if tc.wantErr && err != nil {
				return
			}
			require.NoError(t, err)
			defer session.Close()

			res, err := session.CallTool(ctx, &mcp.CallToolParams{
				Name:      tc.tool,
				Arguments: tc.arguments,
			})
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotEmpty(t, res.Content)
		})
	}
}

func connectMCP(ctx context.Context, env testenv.Environment, endpoint string, token string) (*mcp.ClientSession, error) {
	httpClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
	httpClient.Transport = &tokenTransport{
		base:  httpClient.Transport,
		token: token,
	}

	mcpClient := mcp.NewClient(&mcp.Implementation{
		Name:    "test-client",
		Version: "1.0.0",
	}, nil)

	return mcpClient.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: httpClient,
	}, nil)
}

type tokenTransport struct {
	base  http.RoundTripper
	token string
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(req)
}
