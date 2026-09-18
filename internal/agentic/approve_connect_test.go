package agentic

import (
	"bytes"
	"context"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/pomerium/pomerium/config"
	agenticpb "github.com/pomerium/pomerium/internal/agentic/gen"
	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/mcp"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/endpoints"
	databroker_grpc "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// newTestDataBrokerClient spins up an in-memory databroker over bufconn and
// returns a client for it (mirrors internal/mcp/storage_test.go).
func newTestDataBrokerClient(ctx context.Context, t *testing.T) databroker_grpc.DataBrokerServiceClient {
	t.Helper()

	list := bufconn.Listen(1024 * 1024)
	t.Cleanup(func() { list.Close() })

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	grpcServer := grpc.NewServer()
	databroker_grpc.RegisterDataBrokerServiceServer(grpcServer, srv)
	go func() {
		if err := grpcServer.Serve(list); err != nil {
			t.Errorf("failed to serve: %v", err)
		}
	}()
	t.Cleanup(grpcServer.Stop)

	conn, err := grpc.DialContext(ctx, "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return list.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	return databroker_grpc.NewDataBrokerServiceClient(conn)
}

// mcpConsentConfig returns a config with one MCP server route (with an upstream)
// and one plain route, plus the resolved MCP server info for the MCP route so
// tests can seed the exact upstream-token composite key.
func mcpConsentConfig(t *testing.T, mcpEnabled bool) (*config.Config, mcp.ServerHostInfo) {
	t.Helper()

	toURL, err := url.Parse("https://tool-upstream.example.com")
	require.NoError(t, err)
	mcpPol := config.Policy{
		From: "https://mcp-tool.example.com",
		To:   config.WeightedURLs{{URL: *toURL}},
		ID:   "mcp-tool-route-id",
		MCP:  &config.MCP{Server: &config.MCPServer{}},
	}
	plainPol := config.Policy{From: "https://plain.example.com"}

	flags := config.RuntimeFlags{}
	if mcpEnabled {
		flags[config.RuntimeFlagMCP] = true
	}
	cfg := &config.Config{Options: &config.Options{
		Policies:     []config.Policy{mcpPol, plainPol},
		RuntimeFlags: flags,
	}}

	info, err := mcp.NewServerHostInfoFromPolicy(&mcpPol)
	require.NoError(t, err)
	return cfg, info
}

func runWithMCPServers(id string, servers ...string) *agenticpb.Run {
	return &agenticpb.Run{Id: id, McpServers: servers}
}

// approveHost is the host the consent page is served on: the agentic host, not
// any MCP route's host, now that the AS sits behind its own routes.
const approveHost = "agentic.example.com"

// TestMCPConsents_Connect verifies the consent page surfaces a Connect
// affordance for MCP OAuth servers: not-yet-connected → NeedsOAuth with a Connect
// link on the MCP route's own host returning to the approve host;
// already-connected → NeedsOAuth + Connected and no link; a URL that names no MCP
// server route carries neither.
func TestMCPConsents_Connect(t *testing.T) {
	ctx := testutil.GetContext(t, time.Minute)
	client := newTestDataBrokerClient(ctx, t)
	cfg, info := mcpConsentConfig(t, true)
	h := &Handler{prefix: DefaultPrefix, cfg: cfg, client: databroker_grpc.NewStaticClientGetter(client)}

	run := runWithMCPServers("run-xyz",
		"https://mcp-tool.example.com",
		"https://plain.example.com")

	t.Run("not connected offers a Connect link back to the approve host", func(t *testing.T) {
		rows := h.mcpConsents(ctx, run, "bob", approveHost)
		require.Len(t, rows, 2)

		mcpRow := rows[0]
		assert.Equal(t, "https://mcp-tool.example.com", mcpRow.URL)
		assert.True(t, mcpRow.NeedsOAuth, "an MCP route with an upstream requires connecting")
		assert.False(t, mcpRow.Connected, "bob has no upstream token yet")
		require.NotEmpty(t, mcpRow.ConnectURL)

		cu, err := url.Parse(mcpRow.ConnectURL)
		require.NoError(t, err)
		assert.Equal(t, "mcp-tool.example.com", cu.Host,
			"the Connect endpoint lives on the MCP route's own host")
		assert.Equal(t, endpoints.PathPomeriumMCPConnect, cu.Path)

		redirect, err := url.Parse(cu.Query().Get("redirect_url"))
		require.NoError(t, err)
		assert.Equal(t, approveHost, redirect.Host,
			"connect must return to the approve host, which is legal because the approve route is an MCP client host")
		assert.Equal(t, ApprovePath(DefaultPrefix), redirect.Path, "connect must return to this consent page")
		assert.Equal(t, "run-xyz", redirect.Query().Get("run_id"), "the return link must carry the run id")

		plainRow := rows[1]
		assert.Equal(t, "https://plain.example.com", plainRow.URL)
		assert.False(t, plainRow.NeedsOAuth, "a URL that names no MCP server route needs no connect")
		assert.Empty(t, plainRow.ConnectURL)
	})

	t.Run("connected approver sees no Connect link", func(t *testing.T) {
		storage := mcp.NewStorage(databroker_grpc.NewStaticClientGetter(client))
		require.NoError(t, storage.PutUpstreamMCPToken(ctx, &oauth21proto.UpstreamMCPToken{
			UserId:         "alice",
			RouteId:        info.RouteID,
			UpstreamServer: info.UpstreamURL,
			AccessToken:    "seeded",
			TokenType:      "Bearer",
		}))

		rows := h.mcpConsents(ctx, run, "alice", approveHost)
		require.Len(t, rows, 2)
		assert.True(t, rows[0].NeedsOAuth)
		assert.True(t, rows[0].Connected, "alice already holds an upstream token for the route")
		assert.Empty(t, rows[0].ConnectURL, "a connected server offers no Connect link")
	})
}

// TestConsentPage_RendersConnectError verifies a failed Connect (which redirects
// back here with connect_error set) is surfaced on the page rather than reloading
// silently, and that the reflected value is HTML-escaped.
func TestConsentPage_RendersConnectError(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, consentPage.Execute(&buf, consentPageData{
		UserEmail:    "dmishin@pomerium.com",
		ConnectError: `MCP connection failed <script>alert(1)</script>`,
		ApprovePath:  ApprovePath(DefaultPrefix),
		MCPServers:   []mcpServerConsent{{URL: "https://gke.example", NeedsOAuth: true, ConnectURL: "https://gke.example/.pomerium/mcp/connect"}},
	}))
	out := buf.String()
	assert.Contains(t, out, `class="error"`, "the connect error must render in the error banner")
	assert.Contains(t, out, "MCP connection failed", "the error text must be shown")
	assert.NotContains(t, out, "<script>alert(1)</script>", "the reflected error must be HTML-escaped")

	// With no error the banner is absent.
	buf.Reset()
	require.NoError(t, consentPage.Execute(&buf, consentPageData{UserEmail: "x@e.com"}))
	assert.NotContains(t, buf.String(), `class="error"`)
}

// TestMCPConsents_MCPFlagOff verifies that when the MCP runtime flag is off the
// consent page falls back to plain rows (no Connect affordance), since the
// connect endpoint is not mounted.
func TestMCPConsents_MCPFlagOff(t *testing.T) {
	ctx := testutil.GetContext(t, time.Minute)
	client := newTestDataBrokerClient(ctx, t)
	cfg, _ := mcpConsentConfig(t, false)
	h := &Handler{prefix: DefaultPrefix, cfg: cfg, client: databroker_grpc.NewStaticClientGetter(client)}

	run := runWithMCPServers("run-xyz", "https://mcp-tool.example.com")
	rows := h.mcpConsents(ctx, run, "bob", approveHost)
	require.Len(t, rows, 1)
	assert.Equal(t, "https://mcp-tool.example.com", rows[0].URL)
	assert.False(t, rows[0].NeedsOAuth, "with MCP disabled no Connect affordance is shown")
	assert.Empty(t, rows[0].ConnectURL)
}
