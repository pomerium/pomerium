package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/agentic"
	pommcp "github.com/pomerium/pomerium/internal/mcp"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/pkg/endpoints"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/nullable"
)

const (
	// mcpRouteID pins the route's ID so the seeded UpstreamMCPToken's composite
	// key (user, route, upstream) matches what ext_proc derives at request time.
	mcpRouteID = "agentic-mcp-tool-route"

	seededUpstreamCredential = "seeded-upstream-oauth-access-token"
)

// authRecorder wraps an upstream handler and records the Authorization header
// of every JSON-RPC tools/call POST that actually reaches the upstream.
type authRecorder struct {
	mu    sync.Mutex
	seen  []string
	inner http.Handler
}

func (a *authRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		if bytes.Contains(body, []byte(`"tools/call"`)) {
			a.mu.Lock()
			a.seen = append(a.seen, r.Header.Get("Authorization"))
			a.mu.Unlock()
		}
	}
	a.inner.ServeHTTP(w, r)
}

func (a *authRecorder) toolCallAuths() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.seen...)
}

// runTokenTransport injects the run token on every request, simulating the
// sandbox sidecar's Envoy header injection.
type runTokenTransport struct {
	base  http.RoundTripper
	token string
}

func (t *runTokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(req)
}

// TestRunTokenMCPCredentialInjection pressure-tests the design's egress-custodian
// claim end to end: a run token presented at a real MCP route must (1) act with
// the approving user's authority through the MCP handshake, (2) never reach the
// upstream itself, (3) cause the approver's cached UpstreamMCPToken to be
// injected on tool calls, (4) be subject to mcp_tool PPL with the structured
// JSON-RPC deny that leaves the MCP session usable, and (5) die mid-session on
// revocation. Design doc §1, §3.4, §4.3, §6.3.
func TestRunTokenMCPCredentialInjection(t *testing.T) {
	env := testenv.New(t)
	idp, idpURL := configureJWTIdp(t, env, "workload")

	env.Add(scenarios.NewIDP([]*scenarios.User{
		{Email: "alice@example.com"},
	}))

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.RuntimeFlags == nil {
			cfg.Options.RuntimeFlags = make(config.RuntimeFlags)
		}
		cfg.Options.RuntimeFlags[config.RuntimeFlagAgentic] = true
		cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = true
	}))

	// A real MCP server with two tools; the route's PPL allows only "hello".
	mcpServer := mcpsdk.NewServer(&mcpsdk.Implementation{Name: "tool-server", Version: "1.0.0"}, nil)
	mcpsdk.AddTool(mcpServer, &mcpsdk.Tool{Name: "hello", Description: "greets"},
		func(_ context.Context, _ *mcpsdk.CallToolRequest, _ any) (*mcpsdk.CallToolResult, any, error) {
			return &mcpsdk.CallToolResult{
				Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: "hello from the tool server"}},
			}, nil, nil
		})
	mcpsdk.AddTool(mcpServer, &mcpsdk.Tool{Name: "forbidden", Description: "must never run"},
		func(_ context.Context, _ *mcpsdk.CallToolRequest, _ any) (*mcpsdk.CallToolResult, any, error) {
			return &mcpsdk.CallToolResult{
				Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: "THE FORBIDDEN TOOL RAN"}},
			}, nil, nil
		})

	recorder := &authRecorder{inner: mcpsdk.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcpsdk.Server { return mcpServer }, nil)}

	up := upstreams.HTTP(nil, upstreams.WithDisplayName("MCP Tool Server"))
	up.Handle("/", recorder.ServeHTTP)

	toAddr := values.Bind(up.Addr(), func(addr string) string {
		return fmt.Sprintf("http://%s", addr)
	})

	// The MCP route declares run-token acceptance like any other route. Being an
	// MCP server is no longer enough on its own: with the run's origin grant gone,
	// an approved run token would otherwise reach every MCP route in the
	// deployment and could spend the approver's connected upstream credentials
	// there.
	mcpRoute := up.Route().
		From(env.SubdomainURL("mcp-tool")).
		To(toAddr).
		PPL(`
- allow:
    and:
      - claim/email: alice@example.com
- deny:
    or:
      - mcp_tool:
          not: hello
`).
		Policy(func(p *config.Policy) {
			p.ID = mcpRouteID
			p.MCP = &config.MCP{Server: &config.MCPServer{}}
			p.BearerTokenFormat = nullable.From(configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_AGENTIC_RUN_TOKEN)
		})

	// The three routes the AS sits behind.
	as := newAgenticRoutes(t, env, "workload",
		`{"allow":{"and":[{"claim/sub": "system:serviceaccount:default:harness"}]}}`,
		`{"allow":{"and":[{"claim/kubernetes.io.serviceaccount.name": "executor"}]}}`,
		`{"allow":{"and":[{"domain": "example.com"}]}}`)

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	now := time.Now()
	harnessJWT := workloadJWT(idp, idpURL.Value(), "system:serviceaccount:default:harness", now, nil)
	sidecarJWT := workloadJWT(idp, idpURL.Value(), "system:serviceaccount:default:executor", now,
		podClaims("executor", "run-pod-1", "pod-uid-1"))

	// --- 1. Interactive flow: create pending run scoped to the MCP route. ---
	resp, body := postJSON(t, up, as.summon, runsPath, bearer(harnessJWT), map[string]any{
		"mcp_servers": []string{mcpRoute.URL().Value()},
		"ttl_seconds": 600,
		"prompt":      "Call the hello tool",
		"executor":    executorSeal("executor", "run-pod-1", "pod-uid-1"),
	})
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create pending run: %v", body)
	runID, _ := body["run_id"].(string)
	require.NotEmpty(t, runID)

	// --- 2. Bind the executor; pending run polls authorization_pending. ---
	resp, body = postJSON(t, up, as.token, tokenPath, bearer(sidecarJWT), map[string]any{})
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "pending run must not issue a token: %v", body)
	require.Equal(t, "authorization_pending", body["error"])

	// --- 3. Alice approves on the consent page, served on the agentic host. ---
	browser := newBrowsers()
	status, page := browser.consentGet(t, up, as.approve, "alice@example.com", runID)
	require.Equal(t, http.StatusOK, status, "consent page must render on the agentic host")

	// The route is an MCP server route requiring upstream OAuth and alice has not
	// connected it, so the consent page must surface a Connect link before she
	// approves — otherwise the agent, acting as alice, could not call the tool.
	assert.Contains(t, page, endpoints.PathPomeriumMCPConnect,
		"consent page must offer a Connect link for the unconnected MCP route")

	status, _, _ = browser.approvePost(t, up, as.approve, "alice@example.com", extractApprovalCode(t, page))
	require.Equal(t, http.StatusSeeOther, status, "approval must succeed and redirect to the sessions page")

	// --- 4. Poll again: run token issued. ---
	resp, body = postJSON(t, up, as.token, tokenPath, bearer(sidecarJWT), map[string]any{})
	require.Equal(t, http.StatusOK, resp.StatusCode, "token issuance after approval: %v", body)
	runToken, _ := body["access_token"].(string)
	require.True(t, strings.HasPrefix(runToken, agentic.RunTokenPrefix))

	// The approver's identity is the injection key: ext_proc looks up the
	// UpstreamMCPToken by the session's user id, which for an approved run is
	// run.Sub (the approver's user-record id).
	ctx := env.Context()
	dbClient := env.NewDataBrokerServiceClient()
	run, err := agentic.GetRun(ctx, dbClient, runID)
	require.NoError(t, err)
	require.NotEmpty(t, run.GetSub(), "an approved run must carry the approver's user id")

	// --- 5. Drive a real MCP session through the route with the run token. ---
	httpClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
	httpClient.Transport = &runTokenTransport{base: httpClient.Transport, token: runToken}

	mcpClient := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "sandbox-agent", Version: "1.0.0"}, nil)
	session, err := mcpClient.Connect(ctx, &mcpsdk.StreamableClientTransport{
		Endpoint:   mcpRoute.URL().Value(),
		HTTPClient: httpClient,
	}, nil)
	require.NoError(t, err, "MCP initialize through the route must succeed with a run token")
	defer session.Close()

	// --- 6. tools/call before any upstream credential is cached: the call
	// succeeds, and the upstream must see NO Authorization header — in
	// particular the run token must never cross to the upstream. ---
	result, err := session.CallTool(ctx, &mcpsdk.CallToolParams{Name: "hello"})
	require.NoError(t, err, "in-scope tools/call must succeed")
	require.NotEmpty(t, result.Content)

	auths := recorder.toolCallAuths()
	require.NotEmpty(t, auths, "the upstream must have observed the tools/call")
	assert.Equal(t, "", auths[len(auths)-1],
		"with no cached upstream credential the upstream must see no Authorization header")

	// --- 7. Seed the approver's upstream OAuth token (what /connect would have
	// stored) and call again: Pomerium must inject it. This is the
	// egress-custodian headline. ---
	storage := pommcp.NewStorage(databrokerpb.NewStaticClientGetter(dbClient))
	require.NoError(t, storage.PutUpstreamMCPToken(ctx, &oauth21proto.UpstreamMCPToken{
		UserId:         run.GetSub(),
		RouteId:        mcpRouteID,
		UpstreamServer: "http://" + up.Addr().Value(),
		AccessToken:    seededUpstreamCredential,
		TokenType:      "Bearer",
	}))

	result, err = session.CallTool(ctx, &mcpsdk.CallToolParams{Name: "hello"})
	require.NoError(t, err)
	require.NotEmpty(t, result.Content)

	auths = recorder.toolCallAuths()
	assert.Equal(t, "Bearer "+seededUpstreamCredential, auths[len(auths)-1],
		"Pomerium must inject the approver's upstream credential on the tool call")

	// --- 8. mcp_tool PPL gates tools per call: the forbidden tool gets the
	// structured JSON-RPC deny, and the deny must not kill the MCP session. ---
	_, err = session.CallTool(ctx, &mcpsdk.CallToolParams{Name: "forbidden"})
	require.Error(t, err, "the forbidden tool must be denied by mcp_tool PPL")
	assert.Contains(t, err.Error(), "access denied", "the deny must be the structured JSON-RPC error")

	result, err = session.CallTool(ctx, &mcpsdk.CallToolParams{Name: "hello"})
	require.NoError(t, err, "a structured deny must leave the MCP session usable (deny → approve → retry)")
	require.NotEmpty(t, result.Content)

	for _, a := range recorder.toolCallAuths() {
		assert.NotContains(t, a, agentic.RunTokenPrefix, "the run token must never reach the upstream")
	}

	// --- 9. Revocation cuts the run off mid-session on the MCP path too. ---
	run, err = agentic.GetRun(ctx, dbClient, runID)
	require.NoError(t, err)
	run.Revoked = true
	require.NoError(t, agentic.PutRun(ctx, dbClient, run))

	// Require the REVOCATION error specifically, not merely any error. A bare
	// err != nil is also satisfied by a transient databroker, transport or MCP
	// session failure — and the authorize path deliberately propagates
	// codes.Unavailable as retryable, so that is a real path to a green test that
	// proves nothing. "access denied" is the structured JSON-RPC deny, as asserted
	// for the mcp_tool PPL case above.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		_, err := session.CallTool(ctx, &mcpsdk.CallToolParams{Name: "hello"})
		if !assert.Error(c, err) {
			return
		}
		// "Forbidden" is the 403 the authorize path returns for a revoked run: the
		// credential itself is rejected, so the call fails at the transport rather
		// than coming back as a structured JSON-RPC error. That is the opposite of
		// the mcp_tool deny asserted above, where the run is still valid and only
		// one tool is refused.
		assert.Contains(c, err.Error(), "Forbidden",
			"the call must fail because the run was revoked, not for an unrelated reason")
	}, 10*time.Second, 200*time.Millisecond, "revocation must take effect on the next MCP request")
}
