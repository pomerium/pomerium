package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/pkg/endpoints"
)

// TestMCPUpstreamOAuthPreRegistered tests the pre-registered client credentials
// flow where upstream_oauth2 provides client_id, client_secret, and static
// endpoints. This is the flow used when an admin has pre-registered an OAuth app
// with a provider like Google or GitHub.
//
// Unlike the DCR fallback test, this test:
//   - Provides static auth_url and token_url (no PRM or AS metadata discovery)
//   - Provides pre-registered client_id and client_secret (no CIMD or DCR)
//   - The mock AS has NO /register endpoint (DCR is not needed)
//   - The upstream MCP server has NO PRM endpoints (static config bypasses discovery)
func TestMCPUpstreamOAuthPreRegistered(t *testing.T) {
	env := testenv.New(t)
	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.RuntimeFlags == nil {
			cfg.Options.RuntimeFlags = make(config.RuntimeFlags)
		}
		cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = true
		cfg.Options.MCPAllowedClientIDDomains = []string{"*.localhost.pomerium.io"}
		cfg.Options.MCPAllowedASMetadataDomains = []string{"127.0.0.1", "localhost"}
	}))

	idp := scenarios.NewIDP([]*scenarios.User{{Email: "user@example.com"}})
	env.Add(idp)

	const (
		preRegClientID     = "pre-reg-client-id"
		preRegClientSecret = "pre-reg-client-secret"
		accessToken        = "upstream-pre-reg-access-token"
	)

	var mu sync.Mutex
	authorizationCodes := map[string]string{}
	var tokenEndpointCalled bool
	var tokenEndpointClientID string
	var tokenEndpointClientSecret string

	var asServer *httptest.Server
	asServer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/authorize":
			clientID := r.URL.Query().Get("client_id")
			redirectURI := r.URL.Query().Get("redirect_uri")
			state := r.URL.Query().Get("state")
			if clientID == "" || redirectURI == "" || state == "" {
				http.Error(w, "missing required oauth params", http.StatusBadRequest)
				return
			}
			if clientID != preRegClientID {
				http.Error(w, "unknown client_id: expected pre-registered ID", http.StatusBadRequest)
				return
			}

			code := "pre-reg-auth-code"
			mu.Lock()
			authorizationCodes[code] = clientID
			mu.Unlock()

			u, err := url.Parse(redirectURI)
			if err != nil {
				http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
				return
			}
			q := u.Query()
			q.Set("code", code)
			q.Set("state", state)
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusFound)

		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid form", http.StatusBadRequest)
				return
			}
			if r.Form.Get("grant_type") != "authorization_code" {
				http.Error(w, "unsupported grant_type", http.StatusBadRequest)
				return
			}
			code := r.Form.Get("code")
			clientID := r.Form.Get("client_id")
			clientSecret := r.Form.Get("client_secret")
			if code == "" || clientID == "" {
				http.Error(w, "missing code or client_id", http.StatusBadRequest)
				return
			}

			mu.Lock()
			expectedClientID := authorizationCodes[code]
			tokenEndpointCalled = true
			tokenEndpointClientID = clientID
			tokenEndpointClientSecret = clientSecret
			mu.Unlock()

			if expectedClientID == "" || expectedClientID != clientID {
				http.Error(w, "invalid code/client_id", http.StatusBadRequest)
				return
			}

			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  accessToken,
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "upstream-pre-reg-refresh-token",
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer asServer.Close()

	// Append the AS server's cert to the test env's CA bundle.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: asServer.Certificate().Raw})
	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.CAFile != "" {
			existingCA, readErr := os.ReadFile(cfg.Options.CAFile)
			require.NoError(t, readErr)
			combined := append(existingCA, certPEM...)
			combinedPath := t.TempDir() + "/combined-ca.pem"
			require.NoError(t, os.WriteFile(combinedPath, combined, 0o600))
			cfg.Options.CAFile = combinedPath
		}
	}))

	// Set up the upstream MCP server — no PRM endpoints since static config
	// bypasses discovery entirely.
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "pre-reg-upstream", Version: "1.0.0"}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "greet", Description: "Returns a greeting"}, func(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "hello from pre-registered upstream"}},
		}, nil, nil
	})
	streamHandler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server { return mcpServer }, nil)

	upstream := upstreams.HTTP(nil, upstreams.WithDisplayName("Pre-Registered MCP Upstream"))
	upstream.Handle("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+accessToken {
			w.Header().Set("WWW-Authenticate", `Bearer realm="OAuth", error="invalid_token", error_description="Missing or invalid access token"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		streamHandler.ServeHTTP(w, r)
	})
	// No PRM well-known endpoints — static endpoints bypass discovery.

	route := upstream.Route().
		From(env.SubdomainURL("mcp-pre-registered")).
		Policy(func(p *config.Policy) {
			p.AllowedDomains = []string{"example.com"}
			p.MCP = &config.MCP{Server: &config.MCPServer{
				UpstreamOAuth2: &config.UpstreamOAuth2{
					ClientID:     preRegClientID,
					ClientSecret: preRegClientSecret,
					Endpoint: config.OAuth2Endpoint{
						AuthURL:  asServer.URL + "/authorize",
						TokenURL: asServer.URL + "/token",
					},
				},
			}}
		})
	env.AddUpstream(upstream)

	// Client route for obtaining the user's Pomerium token.
	clientUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("MCP Client Proxy (Pre-Reg)"))
	clientUpstream.Handle("/token", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "missing or invalid authorization header", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(strings.TrimPrefix(auth, "Bearer ")))
	})
	clientRoute := clientUpstream.Route().
		From(env.SubdomainURL("mcp-client-pre-registered")).
		PPL(`
- allow:
    and:
      - domain:
          is: example.com
`).
		Policy(func(p *config.Policy) {
			p.MCP = &config.MCP{Client: &config.MCPClient{}}
		})
	env.AddUpstream(clientUpstream)

	env.Start()
	snippets.WaitStartupComplete(env)

	// Obtain user token via the client route.
	resp, err := clientUpstream.Get(clientRoute,
		upstreams.Path("/token"),
		upstreams.AuthenticateAs("user@example.com"),
		upstreams.ClientHook(func(c *http.Client) *http.Client {
			c.Jar, _ = cookiejar.New(nil)
			return c
		}),
	)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	userTokenBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	userToken := string(userTokenBytes)

	// Bootstrap upstream OAuth session via ConnectGet before MCP initialize.
	browser := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
	browser.Jar, _ = cookiejar.New(nil)
	var transport *http.Transport
	switch rt := browser.Transport.(type) {
	case *upstreams.Transport:
		transport = rt.Base.Clone()
	case *http.Transport:
		transport = rt.Clone()
	default:
		transport = http.DefaultTransport.(*http.Transport).Clone()
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	if env.ServerCAs() != nil {
		transport.TLSClientConfig.RootCAs = env.ServerCAs().Clone()
	} else {
		transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	}
	transport.TLSClientConfig.RootCAs.AddCert(asServer.Certificate())
	browser.Transport = transport

	// Authenticate with the route first.
	authReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		route.URL().Value()+endpoints.PathPomeriumMCPRoutes, nil)
	require.NoError(t, err)
	authResp, err := upstreams.AuthenticateFlow(t.Context(), browser, authReq, "user@example.com", true)
	require.NoError(t, err)
	authResp.Body.Close()

	// Initiate the connect flow to trigger upstream OAuth.
	redirectTarget := clientRoute.URL().Value() + "/after-connect"
	connectURL := route.URL().Value() + endpoints.PathPomeriumMCPConnect +
		"?redirect_url=" + url.QueryEscape(redirectTarget)
	connectReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, connectURL, nil)
	require.NoError(t, err)
	connectResp, err := browser.Do(connectReq)
	require.NoError(t, err)
	defer connectResp.Body.Close()
	require.NotEqual(t, http.StatusUnauthorized, connectResp.StatusCode)

	// Connect MCP session and call a tool.
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	session, err := connectMCP(ctx, env, route.URL().Value(), userToken)
	require.NoError(t, err)
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "greet"})
	require.NoError(t, err)
	require.NotEmpty(t, result.Content)

	// Verify the token endpoint received the correct pre-registered credentials.
	mu.Lock()
	defer mu.Unlock()
	assert.True(t, tokenEndpointCalled, "expected token endpoint to be called")
	assert.Equal(t, preRegClientID, tokenEndpointClientID, "token endpoint should receive the pre-registered client_id")
	assert.Equal(t, preRegClientSecret, tokenEndpointClientSecret, "token endpoint should receive the pre-registered client_secret")
}
