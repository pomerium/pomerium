package configapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/protobuf/proto"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/config/configconnect"
	"github.com/pomerium/pomerium/pkg/mcp/configapi"
)

// connectMCP opens an MCP streamable-HTTP client session against endpoint and
// cleans it up when the test ends.
func connectMCP(t *testing.T, endpoint string) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)

	client := mcp.NewClient(&mcp.Implementation{Name: "configapi-test", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: endpoint}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// newTestServer wraps a ConfigServiceHandler stub in an httptest.Server that
// exposes the MCP bridge produced by configapi.NewHandler.
func newTestServer(t *testing.T, impl configconnect.ConfigServiceHandler, opts ...configapi.Option) string {
	t.Helper()
	_, connectHandler := configconnect.NewConfigServiceHandler(impl)
	ts := httptest.NewServer(configapi.NewHandler(connectHandler, opts...))
	t.Cleanup(ts.Close)
	return ts.URL
}

func TestMCPConfigAPI_ToolDiscovery(t *testing.T) {
	t.Parallel()

	session := connectMCP(t, newTestServer(t, configconnect.UnimplementedConfigServiceHandler{}))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	tools, err := session.ListTools(ctx, nil)
	require.NoError(t, err)

	names := map[string]*mcp.Tool{}
	for _, tool := range tools.Tools {
		names[tool.Name] = tool
	}

	expected := []string{
		"create_route", "get_route", "list_routes", "update_route", "delete_route",
		"create_policy", "get_policy", "list_policies", "update_policy", "delete_policy",
		"create_service_account", "get_service_account", "list_service_accounts",
		"update_service_account", "delete_service_account",
		"create_key_pair", "get_key_pair", "list_key_pairs", "update_key_pair", "delete_key_pair",
		"get_settings", "list_settings", "update_settings",
	}
	for _, want := range expected {
		assert.Contains(t, names, want, "missing tool %q", want)
	}
	assert.NotContains(t, names, "get_server_info", "get_server_info should be skipped")

	for name, tool := range names {
		require.NotNil(t, tool.InputSchema, "input schema nil for %s", name)
		require.NotNil(t, tool.OutputSchema, "output schema nil for %s", name)
		inType, ok := tool.InputSchema.(map[string]any)["type"].(string)
		require.True(t, ok, "input schema for %s missing type", name)
		assert.Equal(t, "object", inType)
		outType, ok := tool.OutputSchema.(map[string]any)["type"].(string)
		require.True(t, ok, "output schema for %s missing type", name)
		assert.Equal(t, "object", outType)
		assert.NotEmpty(t, tool.Description)
	}
}

func TestMCPConfigAPI_ToolAnnotations(t *testing.T) {
	t.Parallel()

	session := connectMCP(t, newTestServer(t, configconnect.UnimplementedConfigServiceHandler{}))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	tools, err := session.ListTools(ctx, nil)
	require.NoError(t, err)

	byName := map[string]*mcp.Tool{}
	for _, tool := range tools.Tools {
		byName[tool.Name] = tool
	}

	// List / Get: read-only.
	for _, name := range []string{"list_routes", "get_route", "list_policies", "get_settings"} {
		tool := byName[name]
		require.NotNil(t, tool, name)
		require.NotNil(t, tool.Annotations, name)
		assert.True(t, tool.Annotations.ReadOnlyHint, "%s should be ReadOnlyHint", name)
		require.NotNil(t, tool.Annotations.OpenWorldHint, name)
		assert.False(t, *tool.Annotations.OpenWorldHint, "%s OpenWorldHint should be false", name)
	}

	// Create: not destructive, not idempotent.
	for _, name := range []string{"create_route", "create_policy", "create_service_account"} {
		tool := byName[name]
		require.NotNil(t, tool, name)
		require.NotNil(t, tool.Annotations, name)
		require.NotNil(t, tool.Annotations.DestructiveHint, name)
		assert.False(t, *tool.Annotations.DestructiveHint, "%s DestructiveHint should be false", name)
		assert.False(t, tool.Annotations.IdempotentHint, "%s IdempotentHint should be false", name)
	}

	// Update: idempotent, not destructive.
	for _, name := range []string{"update_route", "update_policy", "update_settings"} {
		tool := byName[name]
		require.NotNil(t, tool, name)
		require.NotNil(t, tool.Annotations, name)
		require.NotNil(t, tool.Annotations.DestructiveHint, name)
		assert.False(t, *tool.Annotations.DestructiveHint, "%s DestructiveHint should be false", name)
		assert.True(t, tool.Annotations.IdempotentHint, "%s IdempotentHint should be true", name)
	}

	// Delete: destructive + idempotent.
	for _, name := range []string{"delete_route", "delete_policy", "delete_service_account", "delete_key_pair"} {
		tool := byName[name]
		require.NotNil(t, tool, name)
		require.NotNil(t, tool.Annotations, name)
		require.NotNil(t, tool.Annotations.DestructiveHint, name)
		assert.True(t, *tool.Annotations.DestructiveHint, "%s DestructiveHint should be true", name)
		assert.True(t, tool.Annotations.IdempotentHint, "%s IdempotentHint should be true", name)
	}
}

// routeCRUD is a minimal in-memory stub of ConfigService that tracks a single
// route id so we can exercise the end-to-end dispatch path.
type routeCRUD struct {
	configconnect.UnimplementedConfigServiceHandler
	stored atomic.Value // *configpb.Route
}

func (s *routeCRUD) CreateRoute(_ context.Context, req *connect.Request[configpb.CreateRouteRequest]) (*connect.Response[configpb.CreateRouteResponse], error) {
	if req.Msg.Route == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, nil)
	}
	clone := proto.Clone(req.Msg.Route).(*configpb.Route)
	id := "route-1"
	clone.Id = &id
	s.stored.Store(clone)
	return connect.NewResponse(&configpb.CreateRouteResponse{Route: clone}), nil
}

func (s *routeCRUD) GetRoute(_ context.Context, req *connect.Request[configpb.GetRouteRequest]) (*connect.Response[configpb.GetRouteResponse], error) {
	got, _ := s.stored.Load().(*configpb.Route)
	if got == nil || got.GetId() != req.Msg.Id {
		return nil, connect.NewError(connect.CodeNotFound, nil)
	}
	return connect.NewResponse(&configpb.GetRouteResponse{Route: got}), nil
}

func TestMCPConfigAPI_ToolRoundtrip(t *testing.T) {
	t.Parallel()

	impl := &routeCRUD{}
	session := connectMCP(t, newTestServer(t, impl))
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	createResp, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "create_route",
		Arguments: map[string]any{
			"route": map[string]any{"name": "selftest", "from": "https://a.example", "to": []string{"https://b.example"}},
		},
	})
	require.NoError(t, err)
	require.False(t, createResp.IsError, "create_route returned error: %+v", createResp.Content)

	getResp, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_route",
		Arguments: map[string]any{"id": "route-1"},
	})
	require.NoError(t, err)
	require.False(t, getResp.IsError, "get_route returned error: %+v", getResp.Content)

	missResp, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_route",
		Arguments: map[string]any{"id": "nope"},
	})
	require.NoError(t, err)
	assert.True(t, missResp.IsError, "get_route on missing id should be a tool error")
}

// TestMCPConfigAPI_RequestStamp verifies that WithRequestStamp-registered
// stamps reach the downstream Connect handler's request headers.
func TestMCPConfigAPI_RequestStamp(t *testing.T) {
	t.Parallel()

	got := make(chan string, 1)
	observer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case got <- r.Header.Get("Authorization"):
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":"unimplemented","message":"ok"}`))
		w.WriteHeader(http.StatusOK)
	})

	ts := httptest.NewServer(configapi.NewHandler(observer,
		configapi.WithRequestStamp(func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer Pomerium-test-token")
		}),
	))
	t.Cleanup(ts.Close)

	session := connectMCP(t, ts.URL)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	// Any tool call will do; we just need the stamp to be invoked.
	_, _ = session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_route",
		Arguments: map[string]any{"id": "x"},
	})

	select {
	case authz := <-got:
		assert.Equal(t, "Bearer Pomerium-test-token", authz)
	case <-ctx.Done():
		t.Fatalf("stamp was never observed: %v", ctx.Err())
	}
}
