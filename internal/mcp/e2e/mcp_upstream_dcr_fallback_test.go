package e2e

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/pkg/endpoints"
)

func TestMCPUpstreamOAuthDCRFallback(t *testing.T) {
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

	const accessToken = "upstream-access-token"
	var registrationCalls atomic.Int32
	var mu sync.Mutex
	registeredClientID := ""
	authorizationCodes := map[string]string{}

	var asServer *httptest.Server
	asServer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                asServer.URL,
				"authorization_endpoint":                asServer.URL + "/authorize",
				"token_endpoint":                        asServer.URL + "/token",
				"registration_endpoint":                 asServer.URL + "/register",
				"response_types_supported":              []string{"code"},
				"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
				"code_challenge_methods_supported":      []string{"S256"},
				"client_id_metadata_document_supported": false,
			})
		case "/register":
			registrationCalls.Add(1)
			registeredClientID = "dcr-client-id"
			_ = json.NewEncoder(w).Encode(map[string]any{
				"client_id": registeredClientID,
			})
		case "/authorize":
			clientID := r.URL.Query().Get("client_id")
			redirectURI := r.URL.Query().Get("redirect_uri")
			state := r.URL.Query().Get("state")
			if clientID == "" || redirectURI == "" || state == "" {
				http.Error(w, "missing required oauth params", http.StatusBadRequest)
				return
			}
			if clientID != registeredClientID {
				http.Error(w, "unknown client_id", http.StatusBadRequest)
				return
			}
			code := "test-auth-code"
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
			if code == "" || clientID == "" {
				http.Error(w, "missing code or client_id", http.StatusBadRequest)
				return
			}

			mu.Lock()
			expectedClientID := authorizationCodes[code]
			mu.Unlock()
			if expectedClientID == "" || expectedClientID != clientID {
				http.Error(w, "invalid code/client_id", http.StatusBadRequest)
				return
			}

			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token":  accessToken,
				"token_type":    "Bearer",
				"expires_in":    3600,
				"refresh_token": "upstream-refresh-token",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer asServer.Close()

	certPath := t.TempDir() + "/as-cert.pem"
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: asServer.Certificate().Raw})
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	t.Setenv("SSL_CERT_FILE", certPath)

	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "upstream-server", Version: "1.0.0"}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "hello", Description: "Returns a greeting"}, func(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: "hello from protected upstream"}},
		}, nil, nil
	})
	streamHandler := mcp.NewStreamableHTTPHandler(func(_ *http.Request) *mcp.Server { return mcpServer }, nil)

	upstream := upstreams.HTTP(nil, upstreams.WithDisplayName("Protected MCP Upstream"))
	upstream.Handle("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+accessToken {
			w.Header().Set("WWW-Authenticate", `Bearer realm="OAuth", error="invalid_token", error_description="Missing or invalid access token"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		streamHandler.ServeHTTP(w, r)
	})
	upstream.Handle("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Concrete Notion behavior: PRM resource is origin-only (e.g.
		// https://mcp.notion.com) while MCP endpoint lives at /mcp.
		resourceOrigin := fmt.Sprintf("http://%s", r.Host)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resource":              resourceOrigin,
			"authorization_servers": []string{asServer.URL},
		})
	})

	route := upstream.Route().
		From(env.SubdomainURL("mcp-dcr-fallback")).
		Policy(func(p *config.Policy) {
			p.AllowedDomains = []string{"example.com"}
			p.MCP = &config.MCP{Server: &config.MCPServer{
				AuthorizationServerURL: proto.String(asServer.URL),
				Path:                   proto.String("/mcp"),
			}}
		})
	env.AddUpstream(upstream)

	clientUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("MCP Client Proxy"))
	clientUpstream.Handle("/token", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "missing or invalid authorization header", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(strings.TrimPrefix(auth, "Bearer ")))
	})
	clientRoute := clientUpstream.Route().
		From(env.SubdomainURL("mcp-client-dcr-fallback")).
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

	authReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
		route.URL().Value()+endpoints.PathPomeriumMCPRoutes, nil)
	require.NoError(t, err)
	authResp, err := upstreams.AuthenticateFlow(t.Context(), browser, authReq, "user@example.com", true)
	require.NoError(t, err)
	authResp.Body.Close()

	redirectTarget := clientRoute.URL().Value() + "/after-connect"
	connectURL := route.URL().Value() + endpoints.PathPomeriumMCPConnect +
		"?redirect_url=" + url.QueryEscape(redirectTarget)
	connectReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, connectURL, nil)
	require.NoError(t, err)
	connectResp, err := browser.Do(connectReq)
	require.NoError(t, err)
	defer connectResp.Body.Close()
	require.NotEqual(t, http.StatusUnauthorized, connectResp.StatusCode)

	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()

	session, err := connectMCP(ctx, env, route.URL().Value(), userToken)
	require.NoError(t, err)
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "hello"})
	require.NoError(t, err)
	require.NotEmpty(t, result.Content)

	assert.GreaterOrEqual(t, registrationCalls.Load(), int32(1), "expected DCR registration fallback to be used")
}
