package configapi_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

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

// TestMCPConfigAPI_RequestModifier verifies that WithRequestModifier-registered
// modifiers reach the downstream Connect handler's request headers.
func TestMCPConfigAPI_RequestModifier(t *testing.T) {
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
		configapi.WithRequestModifier(func(req *http.Request) error {
			req.Header.Set("Authorization", "Bearer Pomerium-test-token")
			return nil
		}),
	))
	t.Cleanup(ts.Close)

	session := connectMCP(t, ts.URL)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	// Any tool call will do; we just need the modifier to be invoked.
	_, _ = session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_route",
		Arguments: map[string]any{"id": "x"},
	})

	select {
	case authz := <-got:
		assert.Equal(t, "Bearer Pomerium-test-token", authz)
	case <-ctx.Done():
		t.Fatalf("modifier was never observed: %v", ctx.Err())
	}
}

// TestMCPConfigAPI_ServerMutator verifies that a tool registered via
// WithServerMutator is discoverable and callable, and that the mutator runs
// after the auto-generated tools so the caller sees the same server.
func TestMCPConfigAPI_ServerMutator(t *testing.T) {
	t.Parallel()

	type pingInput struct {
		Echo string `json:"echo" jsonschema:"value to echo back"`
	}
	type pingOutput struct {
		Echoed string `json:"echoed"`
	}

	mutator := func(s *mcp.Server) {
		mcp.AddTool(s, &mcp.Tool{
			Name:        "probe_ping",
			Title:       "Probe Ping",
			Description: "Return the input echoed back. Test-only.",
		}, func(_ context.Context, _ *mcp.CallToolRequest, in pingInput) (*mcp.CallToolResult, pingOutput, error) {
			return nil, pingOutput{Echoed: in.Echo}, nil
		})
	}

	session := connectMCP(t, newTestServer(t, configconnect.UnimplementedConfigServiceHandler{},
		configapi.WithServerMutator(mutator),
	))

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	tools, err := session.ListTools(ctx, nil)
	require.NoError(t, err)
	names := map[string]bool{}
	for _, tool := range tools.Tools {
		names[tool.Name] = true
	}
	assert.True(t, names["probe_ping"], "probe_ping should be registered")
	assert.True(t, names["create_route"], "auto-generated tools should still be registered")

	resp, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "probe_ping",
		Arguments: map[string]any{"echo": "hello"},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError, "probe_ping returned error: %+v", resp.Content)

	out, ok := resp.StructuredContent.(map[string]any)
	require.True(t, ok, "structured content should be a map, got %T", resp.StructuredContent)
	assert.Equal(t, "hello", out["echoed"])
}

// TestMCPConfigAPI_InputSchemaContributor verifies that a contributor can
// inject extra top-level fields into auto-generated tool input schemas, and
// that the contributor runs only on proto-derived tools — not on tools added
// via WithServerMutator (which manage their own schemas).
func TestMCPConfigAPI_InputSchemaContributor(t *testing.T) {
	t.Parallel()

	contributor := func(_ protoreflect.MethodDescriptor, schema map[string]any) map[string]any {
		props, _ := schema["properties"].(map[string]any)
		props["scope_token"] = map[string]any{
			"type":        "string",
			"description": "test-only marker added by contributor",
		}
		required, _ := schema["required"].([]any)
		required = append(required, "scope_token")
		schema["required"] = required
		return schema
	}

	mutator := func(s *mcp.Server) {
		mcp.AddTool(s, &mcp.Tool{
			Name:        "side_tool",
			Description: "Tool added via ServerMutator; should NOT be augmented.",
		}, func(_ context.Context, _ *mcp.CallToolRequest, _ map[string]any) (*mcp.CallToolResult, map[string]any, error) {
			return nil, map[string]any{}, nil
		})
	}

	session := connectMCP(t, newTestServer(t, configconnect.UnimplementedConfigServiceHandler{},
		configapi.WithInputSchemaContributor(contributor),
		configapi.WithServerMutator(mutator),
	))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	tools, err := session.ListTools(ctx, nil)
	require.NoError(t, err)
	byName := map[string]*mcp.Tool{}
	for _, tool := range tools.Tools {
		byName[tool.Name] = tool
	}
	require.Contains(t, byName, "create_route")
	require.Contains(t, byName, "side_tool")

	autoSchema, _ := byName["create_route"].InputSchema.(map[string]any)
	autoProps, _ := autoSchema["properties"].(map[string]any)
	assert.Contains(t, autoProps, "scope_token", "contributor must add field to auto-generated tool schema")
	autoRequired, _ := autoSchema["required"].([]any)
	assert.Contains(t, autoRequired, "scope_token", "contributor must mark added field required")

	sideSchema, _ := byName["side_tool"].InputSchema.(map[string]any)
	sideProps, _ := sideSchema["properties"].(map[string]any)
	assert.NotContains(t, sideProps, "scope_token",
		"contributor must NOT touch ServerMutator-added tools — those manage their own schemas")
}

// TestMCPConfigAPI_PreCall_ShortCircuitsAndMapsErrors verifies that an error
// returned by a PreCall (a) prevents the in-process Connect dispatch and
// (b) flows through ErrorMappers, so it reaches the MCP client as an MCP
// error rather than a raw transport failure.
func TestMCPConfigAPI_PreCall_ShortCircuitsAndMapsErrors(t *testing.T) {
	t.Parallel()

	preCall := func(_ context.Context, _ protoreflect.MethodDescriptor, _ map[string]any, _ func(string, string)) error {
		return connect.NewError(connect.CodeInvalidArgument, errors.New("scope is required"))
	}

	mappedSentinel := errors.New("scope is required (mapped)")
	mapper := func(_ context.Context, _ protoreflect.MethodDescriptor, err error) error {
		var ce *connect.Error
		if errors.As(err, &ce) && ce.Code() == connect.CodeInvalidArgument {
			return connect.NewError(connect.CodeInvalidArgument, mappedSentinel)
		}
		return err
	}

	dispatched := atomic.Bool{}
	stopHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		dispatched.Store(true)
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(configapi.NewHandler(stopHandler,
		configapi.WithPreCall(preCall),
		configapi.WithErrorMapper(mapper),
	))
	t.Cleanup(ts.Close)

	session := connectMCP(t, ts.URL)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resp, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_route",
		Arguments: map[string]any{"id": "x"},
	})
	require.NoError(t, err, "tool errors are surfaced via resp.IsError, not transport error")
	require.True(t, resp.IsError, "PreCall short-circuit must surface as MCP tool error")
	assert.False(t, dispatched.Load(), "PreCall returning an error must skip the Connect dispatch")

	// The mapped sentinel proves ErrorMappers ran on the PreCall error.
	var bodyText strings.Builder
	for _, part := range resp.Content {
		if tc, ok := part.(*mcp.TextContent); ok {
			bodyText.WriteString(tc.Text)
		}
	}
	assert.Contains(t, bodyText.String(), "(mapped)",
		"PreCall errors must flow through ErrorMappers; otherwise a raw transport error reaches the client. Got: %s", bodyText.String())
}

// TestMCPConfigAPI_PreCall_HeadersForwardedToUpdateSparseMergeGet verifies
// that headers stamped by a PreCall reach the implicit internal Get* call
// that Update* tools use for sparse-patch merging. Without this, an Update
// would do its scoping Get against the user's default scope while the outer
// Update applied the merged patch to the PreCall-supplied scope — silently
// overwriting an unrelated entity in another scope.
func TestMCPConfigAPI_PreCall_HeadersForwardedToUpdateSparseMergeGet(t *testing.T) {
	t.Parallel()

	type captured struct {
		path   string
		header string
	}
	calls := make(chan captured, 4)
	observer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case calls <- captured{path: r.URL.Path, header: r.Header.Get("X-Test-Scope")}:
		default:
		}
		// Returning a recognised entity-shaped JSON keeps applyUpdatePatch
		// happy: it expects the response to deserialize into a message with
		// a single nested entity matching the input's entity type.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"route":{"id":"r-1"}}`))
	})

	preCall := func(_ context.Context, _ protoreflect.MethodDescriptor, _ map[string]any, setHeader func(string, string)) error {
		setHeader("X-Test-Scope", "alpha")
		return nil
	}

	ts := httptest.NewServer(configapi.NewHandler(observer, configapi.WithPreCall(preCall)))
	t.Cleanup(ts.Close)
	session := connectMCP(t, ts.URL)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "update_route",
		Arguments: map[string]any{"route": map[string]any{"id": "r-1", "name": "renamed"}},
	})
	require.NoError(t, err)

	seen := []captured{}
loop:
	for {
		select {
		case c := <-calls:
			seen = append(seen, c)
		case <-time.After(100 * time.Millisecond):
			break loop
		}
	}
	require.GreaterOrEqual(t, len(seen), 2,
		"update_route must produce both an internal Get and an Update dispatch; saw %d", len(seen))
	for _, c := range seen {
		assert.Equal(t, "alpha", c.header,
			"every dispatch in an Update tool — including the internal sparse-merge Get — must receive the PreCall headers; %s did not", c.path)
	}
}

// TestMCPConfigAPI_PreCall_OverridesStaticModifier verifies that when both
// WithRequestModifier and a PreCall set the same Connect header, the PreCall
// value wins. Per-call values are intentionally more specific than static
// modifiers; allowing the static value to leak through would silently mis-scope
// PreCall-driven calls.
func TestMCPConfigAPI_PreCall_OverridesStaticModifier(t *testing.T) {
	t.Parallel()

	got := make(chan string, 1)
	observer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case got <- r.Header.Get("X-Test-Scope"):
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})

	ts := httptest.NewServer(configapi.NewHandler(observer,
		configapi.WithRequestModifier(func(req *http.Request) error {
			req.Header.Set("X-Test-Scope", "from-modifier")
			return nil
		}),
		configapi.WithPreCall(func(_ context.Context, _ protoreflect.MethodDescriptor, _ map[string]any, setHeader func(string, string)) error {
			setHeader("X-Test-Scope", "from-precall")
			return nil
		}),
	))
	t.Cleanup(ts.Close)
	session := connectMCP(t, ts.URL)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, _ = session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_route",
		Arguments: map[string]any{"id": "x"},
	})

	select {
	case v := <-got:
		assert.Equal(t, "from-precall", v, "PreCall headers must override static modifiers for the same key")
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

// TestMCPConfigAPI_PreCall_StampsHeadersAndStripsArgs verifies the per-call
// header callback reaches the downstream Connect handler and that args
// removed by a PreCall do not appear in the request body.
func TestMCPConfigAPI_PreCall_StampsHeadersAndStripsArgs(t *testing.T) {
	t.Parallel()

	type captured struct {
		headers http.Header
		body    string
	}
	got := make(chan captured, 1)
	observer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		select {
		case got <- captured{headers: r.Header.Clone(), body: string(body)}:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":"unimplemented","message":"ok"}`))
		w.WriteHeader(http.StatusOK)
	})

	preCall := func(_ context.Context, _ protoreflect.MethodDescriptor, args map[string]any, setHeader func(string, string)) error {
		setHeader("X-Test-Scope", "alpha")
		delete(args, "scope_token")
		return nil
	}

	contributor := func(_ protoreflect.MethodDescriptor, schema map[string]any) map[string]any {
		props, _ := schema["properties"].(map[string]any)
		props["scope_token"] = map[string]any{"type": "string"}
		return schema
	}

	ts := httptest.NewServer(configapi.NewHandler(observer,
		configapi.WithInputSchemaContributor(contributor),
		configapi.WithPreCall(preCall),
	))
	t.Cleanup(ts.Close)

	session := connectMCP(t, ts.URL)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, _ = session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_route",
		Arguments: map[string]any{"id": "x", "scope_token": "secret-from-args"},
	})

	select {
	case c := <-got:
		assert.Equal(t, "alpha", c.headers.Get("X-Test-Scope"),
			"setHeader callback must propagate to the in-process Connect request")
		assert.NotContains(t, c.body, "scope_token",
			"args removed by PreCall must not appear in the dispatched request body")
		assert.NotContains(t, c.body, "secret-from-args",
			"the PreCall stripped the field, but its value still reached the wire — strip is broken")
	case <-ctx.Done():
		t.Fatalf("downstream handler never observed: %v", ctx.Err())
	}
}

// TestMCPConfigAPI_ListLimitClamp_Enforced verifies that for every shape the
// LLM can supply `limit` in (absent, zero, in-range, exactly the cap, over
// the cap, max-uint64-as-string), the request the downstream Connect handler
// observes carries a limit ≤ 100. Defends the 5 MiB response cap in
// caller.go from being defeated by a single overlong list call.
func TestMCPConfigAPI_ListLimitClamp_Enforced(t *testing.T) {
	t.Parallel()

	got := make(chan string, 8)
	observer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		select {
		case got <- string(body):
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"routes":[],"totalCount":"0"}`))
	})

	ts := httptest.NewServer(configapi.NewHandler(observer))
	t.Cleanup(ts.Close)

	cases := []struct {
		name string
		args map[string]any
		// observedLimit is the substring we expect to find in the dispatched
		// JSON body. uint64 fields render as `string` in the auto-generated
		// JSON Schema (matching protojson's encoding), so the LLM passes
		// `limit` as a JSON string. uintFromArg parses both forms; the
		// clamp's substitution writes a JSON number, which protojson on the
		// downstream side accepts equivalently.
		observedLimit string
	}{
		{name: "absent", args: map[string]any{}, observedLimit: `"limit":100`},
		{name: "zero", args: map[string]any{"limit": "0"}, observedLimit: `"limit":100`},
		{name: "below cap", args: map[string]any{"limit": "50"}, observedLimit: `"limit":"50"`},
		{name: "exactly the cap", args: map[string]any{"limit": "100"}, observedLimit: `"limit":"100"`},
		{name: "over the cap", args: map[string]any{"limit": "1000"}, observedLimit: `"limit":100`},
		{name: "max-uint64", args: map[string]any{"limit": "18446744073709551615"}, observedLimit: `"limit":100`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset observer state between sub-cases so each call sees its
			// own fresh request body.
			for {
				select {
				case <-got:
				default:
					goto sendCall
				}
			}
		sendCall:
			session := connectMCP(t, ts.URL)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			_, err := session.CallTool(ctx, &mcp.CallToolParams{
				Name:      "list_routes",
				Arguments: tc.args,
			})
			require.NoError(t, err)

			select {
			case body := <-got:
				assert.Contains(t, body, tc.observedLimit,
					"limit must clamp to 100 — got body %q", body)
			case <-ctx.Done():
				t.Fatalf("downstream handler never observed: %v", ctx.Err())
			}
		})
	}
}

// TestMCPConfigAPI_ResponseCapEnforced verifies that a response larger than
// caller.maxResponseBytes (=5 MiB) fails loudly rather than buffering into
// RAM. This is the partner guard to the list-limit clamp: if anything ever
// slips past the clamp (e.g. a non-List* method that doesn't paginate yet),
// we still bound memory.
func TestMCPConfigAPI_ResponseCapEnforced(t *testing.T) {
	t.Parallel()

	const oversizeBytes = 6 << 20 // 6 MiB > 5 MiB cap
	bigPayload := bytes.Repeat([]byte{'a'}, oversizeBytes)

	observer := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Produce a JSON object whose total length exceeds the cap. The
		// content doesn't have to be valid for the response message; the
		// caller fails before it ever reaches protojson.
		_, _ = w.Write([]byte(`{"_padding":"`))
		_, _ = w.Write(bigPayload)
		_, _ = w.Write([]byte(`"}`))
	})

	ts := httptest.NewServer(configapi.NewHandler(observer))
	t.Cleanup(ts.Close)

	session := connectMCP(t, ts.URL)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resp, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_route",
		Arguments: map[string]any{"id": "any"},
	})
	require.NoError(t, err, "tool errors are surfaced via resp.IsError, not transport error")
	require.True(t, resp.IsError, "oversize response must surface as MCP tool error")

	var bodyText strings.Builder
	for _, part := range resp.Content {
		if tc, ok := part.(*mcp.TextContent); ok {
			bodyText.WriteString(tc.Text)
		}
	}
	assert.Contains(t, bodyText.String(), "5242880-byte cap",
		"error text should name the cap so the operator knows what tripped")
}
