package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
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

// TestExtProcHeaderExtraction verifies that ext_proc can read pseudo-headers
// (:authority, :status, :path, :method, :scheme) from Envoy's ext_proc messages.
// This tests against a real Envoy instance to catch encoding issues (e.g. Value vs RawValue).
func TestExtProcHeaderExtraction(t *testing.T) {
	type capturedCall struct {
		RouteCtx    *extproc.RouteContext
		Host        string
		OriginalURL string
		StatusCode  int
		WWWAuth     string
	}

	var (
		mu       sync.Mutex
		captured []capturedCall
	)

	// Create a mock handler that captures what ext_proc passes to it
	handler := &mockUpstreamHandler{
		getUpstreamToken: func(_ context.Context, _ *extproc.RouteContext, _ string) (string, error) {
			return "", nil // no token, let the request go through bare
		},
		handleUpstreamResponse: func(_ context.Context, routeCtx *extproc.RouteContext, host, originalURL string, statusCode int, wwwAuthenticate string) (*extproc.UpstreamAuthAction, error) {
			mu.Lock()
			captured = append(captured, capturedCall{
				RouteCtx:    routeCtx,
				Host:        host,
				OriginalURL: originalURL,
				StatusCode:  statusCode,
				WWWAuth:     wwwAuthenticate,
			})
			mu.Unlock()
			return nil, nil // pass through, don't redirect
		},
	}

	// Also capture raw response headers from the callback
	type rawHeaderEntry struct {
		Key         string
		Value       string
		RawValueLen int
	}
	rawResponseHeaders := make(chan []rawHeaderEntry, 10)
	extProcCallback := func(_ context.Context, _ *extproc.RouteContext, headers *ext_proc_v3.HttpHeaders) {
		var entries []rawHeaderEntry
		if hm := headers.GetHeaders(); hm != nil {
			for _, h := range hm.GetHeaders() {
				entries = append(entries, rawHeaderEntry{
					Key:         h.GetKey(),
					Value:       h.GetValue(),
					RawValueLen: len(h.GetRawValue()),
				})
			}
		}
		rawResponseHeaders <- entries
	}

	env := testenv.New(t)

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.RuntimeFlags == nil {
			cfg.Options.RuntimeFlags = make(config.RuntimeFlags)
		}
		cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = true
		cfg.Options.MCPAllowedClientIDDomains = []string{"*.localhost.pomerium.io"}
	}))

	env.AddOption(pomerium.WithControlPlaneServerOptions(
		controlplane.WithExtProcCallback(extProcCallback),
		controlplane.WithExtProcHandler(handler),
	))

	idp := scenarios.NewIDP([]*scenarios.User{
		{Email: "user@example.com"},
	})
	env.Add(idp)

	// Create an upstream that always returns 401 with WWW-Authenticate header
	upstream401 := upstreams.HTTP(nil, upstreams.WithDisplayName("401 Upstream"))
	upstream401.Handle("/{path...}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="test", resource_metadata="https://example.com/.well-known/oauth-protected-resource"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Unauthorized"))
	})

	route401 := upstream401.Route().
		From(env.SubdomainURL("extproc-headers-test")).
		Policy(func(p *config.Policy) {
			p.AllowedDomains = []string{"example.com"}
			p.MCP = &config.MCP{
				Server: &config.MCPServer{},
			}
		})
	env.AddUpstream(upstream401)

	// Client route for obtaining a bearer token (same pattern as TestExtProcMCPRouteInvocation)
	clientUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("Token Client"))
	clientUpstream.Handle("/token", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "missing authorization", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, strings.TrimPrefix(auth, "Bearer "))
	})
	clientRoute := clientUpstream.Route().
		From(env.SubdomainURL("extproc-headers-token")).
		PPL(`- allow:
    and:
      - domain:
          is: example.com`).
		Policy(func(p *config.Policy) {
			p.MCP = &config.MCP{
				Client: &config.MCPClient{},
			}
		})
	env.AddUpstream(clientUpstream)

	env.Start()
	snippets.WaitStartupComplete(env)

	// Get a bearer token for MCP auth (same approach as existing test)
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

	// Make a request to the 401 upstream using the MCP bearer token
	httpClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, route401.URL().Value()+"/test-path", strings.NewReader(`{"method":"initialize"}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+userToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify the handler received the correct data from ext_proc
	t.Run("handler receives correct status and host", func(t *testing.T) {
		mu.Lock()
		calls := append([]capturedCall{}, captured...)
		mu.Unlock()

		require.NotEmpty(t, calls, "HandleUpstreamResponse should have been called")
		call := calls[len(calls)-1]

		assert.Equal(t, 401, call.StatusCode, "ext_proc should extract :status as 401")
		assert.NotEmpty(t, call.Host, "ext_proc should extract host")
		assert.NotEmpty(t, call.OriginalURL, "ext_proc should build original URL from request headers")
		assert.Contains(t, call.OriginalURL, "/test-path", "original URL should contain the request path")
		assert.Contains(t, call.WWWAuth, "Bearer", "ext_proc should extract www-authenticate header")
		assert.True(t, call.RouteCtx.IsMCP, "route should be marked as MCP")
	})

	// Verify ext_proc passes the downstream host for HostInfo lookups and callback URLs,
	// while originalURL uses the actual upstream host for discovery/PRM.
	// The handler needs both: downstream host for Pomerium-side operations,
	// and the upstream host (via originalURL/RouteContext) for upstream OAuth flows.
	t.Run("handler receives downstream host and upstream originalURL", func(t *testing.T) {
		mu.Lock()
		calls := append([]capturedCall{}, captured...)
		mu.Unlock()

		require.NotEmpty(t, calls, "HandleUpstreamResponse should have been called")
		call := calls[len(calls)-1]

		downstreamURL := route401.URL().Value()
		// The host parameter should be the downstream :authority (for HostInfo lookups and callback URLs)
		assert.Contains(t, call.Host, "localhost.pomerium.io",
			"host passed to handler should be the downstream domain for HostInfo lookups")

		// Original URL should use the actual upstream host (not downstream)
		assert.NotContains(t, call.OriginalURL, "localhost.pomerium.io",
			"original URL should use the upstream host, not the downstream domain")
		assert.Contains(t, call.OriginalURL, "127.0.0.1",
			"original URL should contain the upstream host")

		// RouteContext should carry the upstream host
		assert.Equal(t, "127.0.0.1", call.RouteCtx.UpstreamHost,
			"route context should carry the upstream host from route config")

		t.Logf("downstream URL: %s, handler host: %s, originalURL: %s", downstreamURL, call.Host, call.OriginalURL)
	})

	// Verify the raw response headers from Envoy
	t.Run("raw response headers contain :status", func(t *testing.T) {
		select {
		case entries := <-rawResponseHeaders:
			var statusEntry *rawHeaderEntry
			for i := range entries {
				if entries[i].Key == ":status" {
					statusEntry = &entries[i]
					break
				}
			}
			require.NotNil(t, statusEntry, ":status pseudo-header must be present in response headers; got keys: %v",
				func() []string {
					keys := make([]string, len(entries))
					for i, e := range entries {
						keys[i] = e.Key
					}
					return keys
				}())

			// Check which field Envoy uses for the value
			if statusEntry.Value != "" {
				assert.Equal(t, "401", statusEntry.Value, ":status should be 401 (via Value)")
			} else {
				assert.Greater(t, statusEntry.RawValueLen, 0, ":status should have RawValue if Value is empty")
				t.Logf("Envoy sends :status via RawValue (len=%d), not Value", statusEntry.RawValueLen)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("ext_proc callback was not invoked")
		}
	})
}

// mockUpstreamHandler implements extproc.UpstreamRequestHandler for testing.
type mockUpstreamHandler struct {
	getUpstreamToken       func(ctx context.Context, routeCtx *extproc.RouteContext, host string) (string, error)
	handleUpstreamResponse func(ctx context.Context, routeCtx *extproc.RouteContext, host, originalURL string, statusCode int, wwwAuthenticate string) (*extproc.UpstreamAuthAction, error)
}

func (m *mockUpstreamHandler) GetUpstreamToken(ctx context.Context, routeCtx *extproc.RouteContext, host string) (string, error) {
	if m.getUpstreamToken != nil {
		return m.getUpstreamToken(ctx, routeCtx, host)
	}
	return "", nil
}

func (m *mockUpstreamHandler) HandleUpstreamResponse(ctx context.Context, routeCtx *extproc.RouteContext, host, originalURL string, statusCode int, wwwAuthenticate string) (*extproc.UpstreamAuthAction, error) {
	if m.handleUpstreamResponse != nil {
		return m.handleUpstreamResponse(ctx, routeCtx, host, originalURL, statusCode, wwwAuthenticate)
	}
	return nil, nil
}
