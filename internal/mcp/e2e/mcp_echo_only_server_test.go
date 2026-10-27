package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/nullable"
)

// mcpEchoOnlyServer is an MCP server behind Pomerium, with an open session,
// whose route lets user@example.com call the echo tool but not the hello tool.
type mcpEchoOnlyServer struct {
	url        string
	config     *config.MCPServer
	session    *mcp.ClientSession
	httpClient *http.Client
	recorder   *upstreamRecorder
	helloCalls *atomic.Int32
}

func startMCPEchoOnlyServer(t *testing.T, proto upstreams.Protocol) *mcpEchoOnlyServer {
	env := testenv.New(t)

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.RuntimeFlags == nil {
			cfg.Options.RuntimeFlags = make(config.RuntimeFlags)
		}
		cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = true
		cfg.Options.MCPAllowedClientIDDomains = []string{"*.localhost.pomerium.io"}
		if proto == upstreams.DialHTTP3 {
			cfg.Options.CodecType = nullable.From(configpb.CodecType_CODEC_TYPE_HTTP3)
		}
	}))

	idp := scenarios.NewIDP([]*scenarios.User{
		{Email: "user@example.com"},
	})
	env.Add(idp)

	helloCalls := new(atomic.Int32)
	mcpServer := mcp.NewServer(&mcp.Implementation{
		Name:    "test-server",
		Version: "1.0.0",
	}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{
		Name:        "hello",
		Description: "Returns a greeting",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
		helloCalls.Add(1)
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
	serverRecorder := &upstreamRecorder{next: serverHandler}
	serverUpstream.Handle("/", serverRecorder.ServeHTTP)

	mcpServerConfig := &config.MCPServer{}
	serverRoute := serverUpstream.Route().
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
			p.MCP = &config.MCP{Server: mcpServerConfig}
		})
	env.AddUpstream(serverUpstream)

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
	tokenBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	userToken := string(tokenBytes)

	mcpClient := mcp.NewClient(&mcp.Implementation{
		Name:    "test-client",
		Version: "1.0.0",
	}, nil)
	httpClient := newDownstreamClient(t, env, proto, userToken)
	session, err := mcpClient.Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint:   serverRoute.URL().Value(),
		HTTPClient: httpClient,
	}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })

	return &mcpEchoOnlyServer{
		url:        serverRoute.URL().Value(),
		config:     mcpServerConfig,
		session:    session,
		httpClient: httpClient,
		recorder:   serverRecorder,
		helloCalls: helloCalls,
	}
}

// protocolVersion returns the MCP protocol version the session negotiated.
func (s *mcpEchoOnlyServer) protocolVersion() string {
	return s.session.InitializeResult().ProtocolVersion
}

// post sends body as a JSON POST on the session outside the MCP client, so
// the HTTP status and body sizes are observable. An empty protocolVersion
// omits the MCP-Protocol-Version header.
func (s *mcpEchoOnlyServer) post(ctx context.Context, t testing.TB, exchange string, body []byte, protocolVersion string) (int, bodySizes) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", s.session.ID())
	if protocolVersion != "" {
		req.Header.Set("Mcp-Protocol-Version", protocolVersion)
	}
	req.Header.Set(exchangeHeader, exchange)
	resp, err := s.httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, bodySizes{Request: len(body), Response: len(respBody)}
}

// exchangeHeader names a request so its body sizes can be matched up on both
// sides of the proxy.
const exchangeHeader = "X-Test-Exchange"

// bodySizes holds the request and response body sizes of one HTTP exchange.
type bodySizes struct {
	Request, Response int
}

// upstreamRecorder records the request and response body sizes of each POST
// the wrapped handler serves.
type upstreamRecorder struct {
	next http.Handler

	mu         sync.Mutex
	byExchange map[string]bodySizes
	maxReq     int
}

func (u *upstreamRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		u.next.ServeHTTP(w, r)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	cw := &countingResponseWriter{ResponseWriter: w}
	u.next.ServeHTTP(cw, r)

	u.mu.Lock()
	defer u.mu.Unlock()
	u.maxReq = max(u.maxReq, len(body))
	if exchange := r.Header.Get(exchangeHeader); exchange != "" {
		if u.byExchange == nil {
			u.byExchange = make(map[string]bodySizes)
		}
		u.byExchange[exchange] = bodySizes{Request: len(body), Response: cw.n}
	}
}

func (u *upstreamRecorder) get(exchange string) (bodySizes, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	sizes, ok := u.byExchange[exchange]
	return sizes, ok
}

func (u *upstreamRecorder) maxRequest() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.maxReq
}

// countingResponseWriter counts the response body bytes written through it.
type countingResponseWriter struct {
	http.ResponseWriter
	n int
}

func (w *countingResponseWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.n += n
	return n, err
}

func (w *countingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// newDownstreamClient returns an HTTP client that reaches Pomerium only over
// the given protocol and fails the test if a response arrives over any other.
func newDownstreamClient(t *testing.T, env testenv.Environment, proto upstreams.Protocol, token string) *http.Client {
	tlsConfig := &tls.Config{RootCAs: env.ServerCAs()}

	var base http.RoundTripper
	var wantMajor int
	switch proto {
	case upstreams.DialHTTP1:
		var protocols http.Protocols
		protocols.SetHTTP1(true)
		base = &http.Transport{TLSClientConfig: tlsConfig, Protocols: &protocols}
		wantMajor = 1
	case upstreams.DialHTTP2:
		var protocols http.Protocols
		protocols.SetHTTP2(true)
		base = &http.Transport{TLSClientConfig: tlsConfig, Protocols: &protocols}
		wantMajor = 2
	case upstreams.DialHTTP3:
		h3 := &http3.Transport{TLSClientConfig: tlsConfig}
		t.Cleanup(func() { _ = h3.Close() })
		base = h3
		wantMajor = 3
	default:
		t.Fatalf("unsupported downstream protocol %q", proto)
	}

	return &http.Client{
		Transport: &tokenTransport{
			base:  &protoCheckTransport{t: t, base: base, wantMajor: wantMajor},
			token: token,
		},
	}
}

type protoCheckTransport struct {
	t         *testing.T
	base      http.RoundTripper
	wantMajor int
}

func (p *protoCheckTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := p.base.RoundTrip(req)
	if err == nil && resp.ProtoMajor != p.wantMajor {
		p.t.Errorf("%s %s served over %s, want HTTP/%d", req.Method, req.URL.Path, resp.Proto, p.wantMajor)
	}
	return resp, err
}

// toolCall returns a well-formed JSON-RPC tools/call request for the named
// tool.
func toolCall(id, name string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      name,
			"arguments": map[string]any{"message": "hi"},
		},
	}
}

func mustMarshal(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// newMCPRequest returns a well-formed MCP tools/list POST to url.
func newMCPRequest(ctx context.Context, url string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	return req, nil
}
