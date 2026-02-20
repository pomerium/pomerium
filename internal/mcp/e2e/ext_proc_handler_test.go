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

// mockHandler is a test UpstreamRequestHandler that records calls and returns
// configurable responses.
type mockHandler struct {
	mu sync.Mutex

	// getTokenFunc controls GetUpstreamToken behavior.
	// If nil, returns ("", nil).
	getTokenFunc func(ctx context.Context, routeCtx *extproc.RouteContext, host string) (string, error)

	// handleResponseFunc controls HandleUpstreamResponse behavior.
	// If nil, returns (nil, nil).
	handleResponseFunc func(ctx context.Context, routeCtx *extproc.RouteContext, host, originalURL string, statusCode int, wwwAuthenticate string) (*extproc.UpstreamAuthAction, error)

	// recorded calls
	getTokenCalls        []getTokenCall
	handleResponseCalls  []handleResponseCall
	getTokenNotify       chan struct{}
	handleResponseNotify chan struct{}
}

type getTokenCall struct {
	RouteCtx *extproc.RouteContext
	Host     string
}

type handleResponseCall struct {
	RouteCtx        *extproc.RouteContext
	Host            string
	OriginalURL     string
	StatusCode      int
	WWWAuthenticate string
}

func newMockHandler() *mockHandler {
	return &mockHandler{
		getTokenNotify:       make(chan struct{}, 10),
		handleResponseNotify: make(chan struct{}, 10),
	}
}

func (m *mockHandler) GetUpstreamToken(ctx context.Context, routeCtx *extproc.RouteContext, host string) (string, error) {
	m.mu.Lock()
	m.getTokenCalls = append(m.getTokenCalls, getTokenCall{RouteCtx: routeCtx, Host: host})
	fn := m.getTokenFunc
	m.mu.Unlock()

	defer func() { m.getTokenNotify <- struct{}{} }()

	if fn != nil {
		return fn(ctx, routeCtx, host)
	}
	return "", nil
}

func (m *mockHandler) HandleUpstreamResponse(ctx context.Context, routeCtx *extproc.RouteContext, host, originalURL string, statusCode int, wwwAuthenticate string) (*extproc.UpstreamAuthAction, error) {
	m.mu.Lock()
	m.handleResponseCalls = append(m.handleResponseCalls, handleResponseCall{
		RouteCtx:        routeCtx,
		Host:            host,
		OriginalURL:     originalURL,
		StatusCode:      statusCode,
		WWWAuthenticate: wwwAuthenticate,
	})
	fn := m.handleResponseFunc
	m.mu.Unlock()

	defer func() { m.handleResponseNotify <- struct{}{} }()

	if fn != nil {
		return fn(ctx, routeCtx, host, originalURL, statusCode, wwwAuthenticate)
	}
	return nil, nil
}

func (m *mockHandler) waitGetToken(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case <-m.getTokenNotify:
	case <-time.After(timeout):
		t.Fatal("timed out waiting for GetUpstreamToken call")
	}
}

func (m *mockHandler) waitHandleResponse(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case <-m.handleResponseNotify:
	case <-time.After(timeout):
		t.Fatal("timed out waiting for HandleUpstreamResponse call")
	}
}

func (m *mockHandler) getGetTokenCalls() []getTokenCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]getTokenCall{}, m.getTokenCalls...)
}

func (m *mockHandler) getHandleResponseCalls() []handleResponseCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]handleResponseCall{}, m.handleResponseCalls...)
}

func (m *mockHandler) resetCalls() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.getTokenCalls = nil
	m.handleResponseCalls = nil
	// drain notification channels
	for {
		select {
		case <-m.getTokenNotify:
		case <-m.handleResponseNotify:
		default:
			return
		}
	}
}

// TestExtProcHandlerIntegration tests the ext_proc handler interface with a full
// Pomerium+Envoy stack, verifying token injection and 401/403 interception.
func TestExtProcHandlerIntegration(t *testing.T) {
	handler := newMockHandler()

	env := testenv.New(t)

	// Enable MCP runtime flag
	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.RuntimeFlags == nil {
			cfg.Options.RuntimeFlags = make(config.RuntimeFlags)
		}
		cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = true
		cfg.Options.MCPAllowedClientIDDomains = []string{"*.localhost.pomerium.io"}
	}))

	// Inject mock handler
	env.AddOption(pomerium.WithControlPlaneServerOptions(
		controlplane.WithExtProcHandler(handler),
	))

	// Set up IDP
	idp := scenarios.NewIDP([]*scenarios.User{
		{Email: "user@example.com"},
	})
	env.Add(idp)

	// Create MCP server upstream that can be toggled to return 401/403
	// and captures received request headers via a channel.
	var upstreamStatus int
	var upstreamWWWAuth string
	var upstreamMu sync.Mutex
	receivedAuth := make(chan string, 10)

	setUpstreamBehavior := func(status int, wwwAuth string) {
		upstreamMu.Lock()
		defer upstreamMu.Unlock()
		upstreamStatus = status
		upstreamWWWAuth = wwwAuth
	}
	setUpstreamBehavior(http.StatusOK, "")

	serverUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("MCP Server"))
	serverUpstream.Handle("/", func(w http.ResponseWriter, r *http.Request) {
		receivedAuth <- r.Header.Get("Authorization")

		upstreamMu.Lock()
		status := upstreamStatus
		wwwAuth := upstreamWWWAuth
		upstreamMu.Unlock()

		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			if wwwAuth != "" {
				w.Header().Set("WWW-Authenticate", wwwAuth)
			}
			w.WriteHeader(status)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	drainReceivedAuth := func() {
		for {
			select {
			case <-receivedAuth:
			default:
				return
			}
		}
	}

	waitReceivedAuth := func(t *testing.T) string {
		t.Helper()
		select {
		case auth := <-receivedAuth:
			return auth
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for upstream to receive request")
			return ""
		}
	}

	mcpRoute := serverUpstream.Route().
		From(env.SubdomainURL("mcp-handler-test")).
		Policy(func(p *config.Policy) {
			p.AllowedDomains = []string{"example.com"}
			p.MCP = &config.MCP{
				Server: &config.MCPServer{},
			}
		})
	env.AddUpstream(serverUpstream)

	// Create client route for Pomerium token acquisition
	clientUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("MCP Client"))
	clientUpstream.Handle("/token", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, strings.TrimPrefix(auth, "Bearer "))
	})
	clientRoute := clientUpstream.Route().
		From(env.SubdomainURL("mcp-client-handler")).
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
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return string(b)
	}

	mcpRequest := func(t *testing.T, token, path string) *http.Response {
		t.Helper()
		client := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
		url := mcpRoute.URL().Value() + path
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		require.NoError(t, err)
		return resp
	}

	t.Run("token injection", func(t *testing.T) {
		handler.resetCalls()
		drainReceivedAuth()

		// Configure handler to return a test upstream token
		handler.getTokenFunc = func(_ context.Context, _ *extproc.RouteContext, _ string) (string, error) {
			return "upstream-test-token-12345", nil
		}
		defer func() { handler.getTokenFunc = nil }()

		setUpstreamBehavior(http.StatusOK, "")

		token := getToken("user@example.com")
		resp := mcpRequest(t, token, "/")
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		// The upstream should have received the injected token, not the Pomerium session token
		auth := waitReceivedAuth(t)
		assert.Equal(t, "Bearer upstream-test-token-12345", auth,
			"upstream should receive the injected upstream token")

		// Verify GetUpstreamToken was called with proper context
		handler.waitGetToken(t, 5*time.Second)
		calls := handler.getGetTokenCalls()
		require.NotEmpty(t, calls)
		lastCall := calls[len(calls)-1]
		assert.True(t, lastCall.RouteCtx.IsMCP, "route context should indicate MCP")
		assert.NotEmpty(t, lastCall.RouteCtx.RouteID, "should have route ID")
		assert.NotEmpty(t, lastCall.Host, "should have downstream host")
	})

	t.Run("no token available passes through without injection", func(t *testing.T) {
		handler.resetCalls()
		drainReceivedAuth()

		// Handler returns empty token
		handler.getTokenFunc = func(_ context.Context, _ *extproc.RouteContext, _ string) (string, error) {
			return "", nil
		}
		defer func() { handler.getTokenFunc = nil }()

		setUpstreamBehavior(http.StatusOK, "")

		token := getToken("user@example.com")
		resp := mcpRequest(t, token, "/")
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		// MCP routes strip the Authorization header in the authorize evaluator,
		// so when no upstream token is injected, the upstream sees no auth header.
		auth := waitReceivedAuth(t)
		assert.Empty(t, auth,
			"upstream should receive no Authorization header when no upstream token available")
	})

	t.Run("401 interception with WWW-Authenticate", func(t *testing.T) {
		handler.resetCalls()

		// Handler returns no upstream token (so request goes without injection)
		handler.getTokenFunc = nil

		// Configure upstream to return 401
		setUpstreamBehavior(http.StatusUnauthorized, `Bearer resource_metadata="https://upstream.example.com/.well-known/oauth-protected-resource"`)

		// Configure handler to return a WWW-Authenticate action
		handler.handleResponseFunc = func(_ context.Context, _ *extproc.RouteContext, _, _ string, _ int, _ string) (*extproc.UpstreamAuthAction, error) {
			return &extproc.UpstreamAuthAction{
				WWWAuthenticate: `Bearer authorization_uri="https://auth.example.com/authorize"`,
			}, nil
		}
		defer func() { handler.handleResponseFunc = nil }()

		token := getToken("user@example.com")
		resp := mcpRequest(t, token, "/")
		defer resp.Body.Close()

		// ext_proc should intercept the 401 and return its own 401 with the handler's WWW-Authenticate
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"should return 401 to client")
		assert.Equal(t, `Bearer authorization_uri="https://auth.example.com/authorize"`,
			resp.Header.Get("WWW-Authenticate"),
			"should contain the handler-generated WWW-Authenticate header")

		// Verify HandleUpstreamResponse was called with correct parameters
		handler.waitHandleResponse(t, 5*time.Second)
		calls := handler.getHandleResponseCalls()
		require.NotEmpty(t, calls)
		lastCall := calls[len(calls)-1]
		assert.Equal(t, 401, lastCall.StatusCode, "should pass status code")
		assert.Contains(t, lastCall.WWWAuthenticate, "resource_metadata",
			"should pass upstream WWW-Authenticate")
		assert.True(t, lastCall.RouteCtx.IsMCP, "should be MCP route")
		assert.NotEmpty(t, lastCall.Host, "should have downstream host")
		assert.NotEmpty(t, lastCall.OriginalURL, "should have original URL")
	})

	t.Run("403 interception", func(t *testing.T) {
		handler.resetCalls()
		handler.getTokenFunc = nil

		// Configure upstream to return 403
		setUpstreamBehavior(http.StatusForbidden, "")

		handler.handleResponseFunc = func(_ context.Context, _ *extproc.RouteContext, _, _ string, statusCode int, _ string) (*extproc.UpstreamAuthAction, error) {
			assert.Equal(t, 403, statusCode)
			return &extproc.UpstreamAuthAction{
				WWWAuthenticate: `Bearer error="insufficient_scope"`,
			}, nil
		}
		defer func() { handler.handleResponseFunc = nil }()

		token := getToken("user@example.com")
		resp := mcpRequest(t, token, "/")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Equal(t, `Bearer error="insufficient_scope"`, resp.Header.Get("WWW-Authenticate"))

		handler.waitHandleResponse(t, 5*time.Second)
		calls := handler.getHandleResponseCalls()
		require.NotEmpty(t, calls)
		assert.Equal(t, 403, calls[len(calls)-1].StatusCode)
	})

	t.Run("handler returns nil action passes through upstream response", func(t *testing.T) {
		handler.resetCalls()
		handler.getTokenFunc = nil

		// Configure upstream to return 401
		setUpstreamBehavior(http.StatusUnauthorized, `Bearer realm="test"`)

		// Handler returns nil (pass through)
		handler.handleResponseFunc = func(_ context.Context, _ *extproc.RouteContext, _, _ string, _ int, _ string) (*extproc.UpstreamAuthAction, error) {
			return nil, nil
		}
		defer func() { handler.handleResponseFunc = nil }()

		token := getToken("user@example.com")
		resp := mcpRequest(t, token, "/")
		defer resp.Body.Close()

		// When handler returns nil, the upstream 401 should pass through
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		// The WWW-Authenticate header should be the upstream's original one
		assert.Equal(t, `Bearer realm="test"`, resp.Header.Get("WWW-Authenticate"),
			"upstream WWW-Authenticate should pass through when handler returns nil")

		handler.waitHandleResponse(t, 5*time.Second)
	})

	t.Run("200 response does not trigger handler", func(t *testing.T) {
		handler.resetCalls()
		handler.getTokenFunc = nil
		handler.handleResponseFunc = nil

		setUpstreamBehavior(http.StatusOK, "")

		token := getToken("user@example.com")
		resp := mcpRequest(t, token, "/")
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Give a moment for any async processing
		time.Sleep(200 * time.Millisecond)

		calls := handler.getHandleResponseCalls()
		assert.Empty(t, calls, "HandleUpstreamResponse should not be called for 200 responses")
	})
}
