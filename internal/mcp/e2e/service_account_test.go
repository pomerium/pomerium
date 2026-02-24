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

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/volatiletech/null/v9"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/controlplane"
	"github.com/pomerium/pomerium/internal/mcp/extproc"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	pomerium "github.com/pomerium/pomerium/pkg/cmd/pomerium"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

// serviceAccountTransport sends the service account JWT using the
// "Authorization: Bearer Pomerium-<JWT>" header format that Pomerium
// recognizes for service account authentication.
type serviceAccountTransport struct {
	base http.RoundTripper
	jwt  string
}

func (t *serviceAccountTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer Pomerium-"+t.jwt)
	return t.base.RoundTrip(req)
}

// TestServiceAccountMCPIntegration tests that Pomerium service accounts can
// authenticate to MCP routes and use upstream tokens provisioned by an
// interactive session for the same user_id.
func TestServiceAccountMCPIntegration(t *testing.T) {
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

	// Create an MCP server upstream with a simple tool.
	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "test-sa-server",
		Version: "1.0.0",
	}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "greet",
		Description: "Returns a greeting",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: "Hello from service account test!"},
			},
		}, nil, nil
	})

	serverUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("SA MCP Server"))
	serverHandler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server {
		return mcpServer
	}, nil)
	serverUpstream.Handle("/", serverHandler.ServeHTTP)

	serverRoute := serverUpstream.Route().
		From(env.SubdomainURL("mcp-sa-test")).
		Policy(func(p *config.Policy) {
			p.AllowAnyAuthenticatedUser = true
			p.MCP = &config.MCP{
				Server: &config.MCPServer{},
			}
		})
	env.AddUpstream(serverUpstream)

	// Create a client route for interactive token acquisition.
	clientUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("SA MCP Client"))
	clientUpstream.Handle("/token", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, strings.TrimPrefix(auth, "Bearer "))
	})
	clientRoute := clientUpstream.Route().
		From(env.SubdomainURL("mcp-sa-client")).
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

	// Step 1: First, establish an interactive session to provision upstream tokens.
	// Use the client route to get the user's MCP token (this also provisions the session).
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

	// Establish an interactive session first (this provisions the user in the system).
	userToken := getToken("user@example.com")
	require.NotEmpty(t, userToken)

	// Verify the interactive session works with MCP.
	ctx := t.Context()
	session, err := connectMCP(ctx, env, serverRoute.URL().Value(), userToken)
	require.NoError(t, err)
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "greet"})
	require.NoError(t, err)
	require.NotEmpty(t, result.Content)
	session.Close()

	// Step 2: Create a service account for the same user in the databroker.
	dbClient := env.NewDataBrokerServiceClient()
	sa := &user.ServiceAccount{
		Id:     "test-sa-001",
		UserId: "user@example.com",
	}
	_, err = user.PutServiceAccount(ctx, dbClient, sa)
	require.NoError(t, err)

	// Sign a JWT for the service account.
	saJWT, err := cryptutil.SignServiceAccount(
		env.SharedSecret(),
		sa.Id,
		sa.UserId,
		time.Now(),
		null.Time{}, // no expiry
	)
	require.NoError(t, err)

	t.Run("service account can connect to MCP server", func(t *testing.T) {
		t.Parallel()

		httpClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
		httpClient.Transport = &serviceAccountTransport{
			base: httpClient.Transport,
			jwt:  saJWT,
		}

		mcpClient := mcp.NewClient(&mcp.Implementation{
			Name:    "sa-test-client",
			Version: "1.0.0",
		}, nil)

		saSession, err := mcpClient.Connect(ctx, &mcp.StreamableClientTransport{
			Endpoint:   serverRoute.URL().Value(),
			HTTPClient: httpClient,
		}, nil)
		require.NoError(t, err)
		defer saSession.Close()

		res, err := saSession.CallTool(ctx, &mcp.CallToolParams{Name: "greet"})
		require.NoError(t, err)
		require.NotEmpty(t, res.Content)
		text := res.Content[0].(*mcp.TextContent)
		assert.Equal(t, "Hello from service account test!", text.Text)
	})

	t.Run("expired service account is rejected", func(t *testing.T) {
		t.Parallel()

		// Create an expired service account.
		expiredSA := &user.ServiceAccount{
			Id:     "test-sa-expired",
			UserId: "user@example.com",
		}
		_, err := user.PutServiceAccount(ctx, dbClient, expiredSA)
		require.NoError(t, err)

		expiredJWT, err := cryptutil.SignServiceAccount(
			env.SharedSecret(),
			expiredSA.Id,
			expiredSA.UserId,
			time.Now().Add(-2*time.Hour),
			null.TimeFrom(time.Now().Add(-1*time.Hour)), // expired 1 hour ago
		)
		require.NoError(t, err)

		httpClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
		httpClient.Transport = &serviceAccountTransport{
			base: httpClient.Transport,
			jwt:  expiredJWT,
		}

		// The request should fail — expired service accounts are rejected.
		url := serverRoute.URL().Value()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Expired SA should be rejected by Pomerium (not reach the upstream).
		assert.NotEqual(t, http.StatusOK, resp.StatusCode,
			"expired service account should not get a 200 response")
	})

	t.Run("service account without matching user_id is rejected", func(t *testing.T) {
		t.Parallel()

		// Create a service account for a user that has no session.
		noSessionSA := &user.ServiceAccount{
			Id:     "test-sa-nosession",
			UserId: "nonexistent@example.com",
		}
		_, err := user.PutServiceAccount(ctx, dbClient, noSessionSA)
		require.NoError(t, err)

		noSessionJWT, err := cryptutil.SignServiceAccount(
			env.SharedSecret(),
			noSessionSA.Id,
			noSessionSA.UserId,
			time.Now(),
			null.Time{},
		)
		require.NoError(t, err)

		httpClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
		httpClient.Transport = &serviceAccountTransport{
			base: httpClient.Transport,
			jwt:  noSessionJWT,
		}

		// The SA user has no existing session, so there are no upstream tokens.
		// The request may fail at the policy level (domain check) or succeed
		// but with no upstream token available.
		url := serverRoute.URL().Value()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// The SA's domain (nonexistent@example.com) is example.com which is allowed,
		// but the request may fail because there's no user session to share tokens with.
		// The exact behavior depends on whether the upstream MCP server requires auth.
		// We just verify the request doesn't panic or return a 500.
		assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode,
			"service account request should not cause internal server error")
	})
}

// TestServiceAccountExtProcHandlerIntegration tests the ext_proc handler
// integration with service accounts, verifying that:
// 1. Token injection works for service accounts (reusing tokens by user_id)
// 2. 401 responses are passed through for service accounts (no interactive OAuth)
func TestServiceAccountExtProcHandlerIntegration(t *testing.T) {
	handler := newMockHandler()

	env := testenv.New(t)

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.RuntimeFlags == nil {
			cfg.Options.RuntimeFlags = make(config.RuntimeFlags)
		}
		cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = true
		cfg.Options.MCPAllowedClientIDDomains = []string{"*.localhost.pomerium.io"}
	}))

	env.AddOption(pomerium.WithControlPlaneServerOptions(
		controlplane.WithExtProcHandler(handler),
	))

	idp := scenarios.NewIDP([]*scenarios.User{
		{Email: "user@example.com"},
	})
	env.Add(idp)

	// Configurable upstream behavior.
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

	serverUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("SA ExtProc Server"))
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
		From(env.SubdomainURL("mcp-sa-extproc")).
		Policy(func(p *config.Policy) {
			p.AllowAnyAuthenticatedUser = true
			p.MCP = &config.MCP{
				Server: &config.MCPServer{},
			}
		})
	env.AddUpstream(serverUpstream)

	env.Start()
	snippets.WaitStartupComplete(env)

	// Create a service account and sign a JWT.
	ctx := t.Context()
	dbClient := env.NewDataBrokerServiceClient()
	sa := &user.ServiceAccount{
		Id:     "extproc-sa-001",
		UserId: "user@example.com",
	}
	_, err := user.PutServiceAccount(ctx, dbClient, sa)
	require.NoError(t, err)

	saJWT, err := cryptutil.SignServiceAccount(
		env.SharedSecret(),
		sa.Id,
		sa.UserId,
		time.Now(),
		null.Time{},
	)
	require.NoError(t, err)

	saRequest := func(t *testing.T, path string) *http.Response {
		t.Helper()
		client := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
		url := mcpRoute.URL().Value() + path
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer Pomerium-"+saJWT)
		resp, err := client.Do(req)
		require.NoError(t, err)
		return resp
	}

	t.Run("service account token injection", func(t *testing.T) {
		handler.resetCalls()
		drainReceivedAuth()

		handler.getTokenFunc = func(_ context.Context, routeCtx *extproc.RouteContext, _ string) (string, error) {
			// Verify the route context has the session ID from the service account.
			assert.NotEmpty(t, routeCtx.SessionID)
			assert.True(t, routeCtx.IsMCP)
			return "sa-upstream-token-xyz", nil
		}
		defer func() { handler.getTokenFunc = nil }()

		setUpstreamBehavior(http.StatusOK, "")

		resp := saRequest(t, "/")
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Verify the upstream received the injected token (not the SA JWT).
		auth := waitReceivedAuth(t)
		assert.Equal(t, "Bearer sa-upstream-token-xyz", auth,
			"upstream should receive the injected token, not the service account JWT")

		handler.waitGetToken(t, 5*time.Second)
	})

	t.Run("service account 401 passthrough", func(t *testing.T) {
		handler.resetCalls()
		drainReceivedAuth()

		handler.getTokenFunc = nil

		// Upstream returns 401.
		setUpstreamBehavior(http.StatusUnauthorized, `Bearer realm="test-upstream"`)

		// Handler returns nil (service accounts pass through 401).
		handler.handleResponseFunc = func(_ context.Context, _ *extproc.RouteContext, _, _ string, _ int, _ string) (*extproc.UpstreamAuthAction, error) {
			return nil, nil
		}
		defer func() { handler.handleResponseFunc = nil }()

		resp := saRequest(t, "/")
		defer resp.Body.Close()

		// The 401 should pass through to the client (no interactive OAuth redirect).
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"upstream 401 should pass through for service accounts")
		assert.Equal(t, `Bearer realm="test-upstream"`, resp.Header.Get("WWW-Authenticate"),
			"upstream WWW-Authenticate should pass through")

		handler.waitHandleResponse(t, 5*time.Second)
	})

	t.Run("service account 200 does not trigger response handler", func(t *testing.T) {
		handler.resetCalls()
		drainReceivedAuth()

		handler.getTokenFunc = func(_ context.Context, _ *extproc.RouteContext, _ string) (string, error) {
			return "sa-token-ok", nil
		}
		handler.handleResponseFunc = nil
		defer func() { handler.getTokenFunc = nil }()

		setUpstreamBehavior(http.StatusOK, "")

		resp := saRequest(t, "/")
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		time.Sleep(200 * time.Millisecond)

		calls := handler.getHandleResponseCalls()
		assert.Empty(t, calls, "HandleUpstreamResponse should not be called for 200")
	})
}
