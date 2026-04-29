package configapi_test

import (
	"context"
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

// TestSchemaOmitsSensitive verifies that sensitive fields do not appear in
// tool input schemas the LLM sees.
func TestSchemaOmitsSensitive(t *testing.T) {
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

	cases := []struct {
		tool          string
		schemaPath    []string
		omittedFields []string
	}{
		{
			tool:       "update_route",
			schemaPath: []string{"properties", "route", "properties"},
			omittedFields: []string{
				"tlsClientKey", "kubernetesServiceAccountToken", "idpClientSecret",
			},
		},
		{
			tool:       "update_settings",
			schemaPath: []string{"properties", "settings", "properties"},
			omittedFields: []string{
				"sharedSecret", "cookieSecret", "idpClientSecret", "signingKey",
				"autocertEabKeyId", "autocertEabMacKey", "sshUserCaKey",
			},
		},
	}
	for _, tc := range cases {
		tool, ok := byName[tc.tool]
		require.True(t, ok, "missing tool %s", tc.tool)
		props := descend(t, tool.InputSchema.(map[string]any), tc.schemaPath)
		for _, f := range tc.omittedFields {
			assert.NotContains(t, props, f, "%s should not expose %q", tc.tool, f)
		}
	}
}

func descend(t *testing.T, schema map[string]any, path []string) map[string]any {
	t.Helper()
	m := schema
	for _, k := range path {
		next, ok := m[k].(map[string]any)
		require.True(t, ok, "expected map at key %q in schema, got %T", k, m[k])
		m = next
	}
	return m
}

type settingsCRUD struct {
	configconnect.UnimplementedConfigServiceHandler
	stored atomic.Pointer[configpb.Settings]
}

func (s *settingsCRUD) GetSettings(_ context.Context, _ *connect.Request[configpb.GetSettingsRequest]) (*connect.Response[configpb.GetSettingsResponse], error) {
	got := s.stored.Load()
	if got == nil {
		return connect.NewResponse(&configpb.GetSettingsResponse{Settings: &configpb.Settings{}}), nil
	}
	return connect.NewResponse(&configpb.GetSettingsResponse{Settings: got}), nil
}

func (s *settingsCRUD) UpdateSettings(_ context.Context, req *connect.Request[configpb.UpdateSettingsRequest]) (*connect.Response[configpb.UpdateSettingsResponse], error) {
	clone := proto.Clone(req.Msg.Settings).(*configpb.Settings)
	s.stored.Store(clone)
	return connect.NewResponse(&configpb.UpdateSettingsResponse{Settings: clone}), nil
}

// TestGetScrubsSensitive verifies the response payload has no sensitive
// fields even when the underlying handler returns them.
func TestGetScrubsSensitive(t *testing.T) {
	t.Parallel()

	impl := &settingsCRUD{}
	secret := "super-secret-cookie-XYZ"
	signing := "MIIBOgIBAAJBAJ7..."
	impl.stored.Store(&configpb.Settings{
		CookieSecret: &secret,
		SigningKey:   &signing,
	})

	session := connectMCP(t, newTestServer(t, impl))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resp, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_settings",
		Arguments: map[string]any{"id": "any"},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError, "%+v", resp.Content)
	require.Len(t, resp.Content, 1)
	body := resp.Content[0].(*mcp.TextContent).Text

	assert.NotContains(t, body, secret, "cookie_secret value leaked")
	assert.NotContains(t, body, signing, "signing_key value leaked")
	assert.NotContains(t, body, "cookieSecret", "scrubbed sensitive field should not appear")
	assert.NotContains(t, body, "signingKey", "scrubbed sensitive field should not appear")
}

type routeCRUDWithUpdate struct {
	configconnect.UnimplementedConfigServiceHandler
	stored atomic.Pointer[configpb.Route]
}

func (s *routeCRUDWithUpdate) GetRoute(_ context.Context, req *connect.Request[configpb.GetRouteRequest]) (*connect.Response[configpb.GetRouteResponse], error) {
	got := s.stored.Load()
	if got == nil || got.GetId() != req.Msg.Id {
		return nil, connect.NewError(connect.CodeNotFound, nil)
	}
	return connect.NewResponse(&configpb.GetRouteResponse{Route: got}), nil
}

func (s *routeCRUDWithUpdate) UpdateRoute(_ context.Context, req *connect.Request[configpb.UpdateRouteRequest]) (*connect.Response[configpb.UpdateRouteResponse], error) {
	clone := proto.Clone(req.Msg.Route).(*configpb.Route)
	s.stored.Store(clone)
	return connect.NewResponse(&configpb.UpdateRouteResponse{Route: clone}), nil
}

// TestUpdatePreservesExistingSensitive verifies that an Update* call from MCP
// preserves both sensitive fields and unset non-sensitive fields from the
// existing record.
func TestUpdatePreservesExistingSensitive(t *testing.T) {
	t.Parallel()

	impl := &routeCRUDWithUpdate{}
	id := "route-1"
	existingDesc := "existing"
	existingClientSecret := "client-secret-xyz"
	impl.stored.Store(&configpb.Route{
		Id:              &id,
		From:            "https://existing.example",
		Description:     &existingDesc,
		TlsClientKey:    "PRIVATE-KEY-XYZ",
		IdpClientSecret: &existingClientSecret,
	})

	session := connectMCP(t, newTestServer(t, impl))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resp, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "update_route",
		Arguments: map[string]any{
			"route": map[string]any{
				"id":          id,
				"description": "updated",
			},
		},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError, "%+v", resp.Content)

	got := impl.stored.Load()
	require.NotNil(t, got)
	assert.Equal(t, "updated", got.GetDescription(), "description should be updated")
	assert.Equal(t, "https://existing.example", got.GetFrom(), "from should be preserved (sparse patch)")
	assert.Equal(t, "PRIVATE-KEY-XYZ", got.GetTlsClientKey(), "tls_client_key must be preserved")
	assert.Equal(t, existingClientSecret, got.GetIdpClientSecret(), "idp_client_secret must be preserved")
}

// TestSkippedMethods verifies methods passed to WithSkippedMethods are not
// exposed as tools.
func TestSkippedMethods(t *testing.T) {
	t.Parallel()

	url := newTestServer(t,
		configconnect.UnimplementedConfigServiceHandler{},
		configapi.WithSkippedMethods("CreateKeyPair", "UpdateKeyPair"),
	)
	session := connectMCP(t, url)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	tools, err := session.ListTools(ctx, nil)
	require.NoError(t, err)

	names := map[string]bool{}
	for _, t := range tools.Tools {
		names[t.Name] = true
	}

	assert.False(t, names["create_key_pair"], "create_key_pair should be skipped")
	assert.False(t, names["update_key_pair"], "update_key_pair should be skipped")
	assert.True(t, names["get_key_pair"], "get_key_pair should still be present")
	assert.True(t, names["list_key_pairs"], "list_key_pairs should still be present")
	assert.True(t, names["delete_key_pair"], "delete_key_pair should still be present")
}

// TestResponseEnricherAppends verifies registered enrichers contribute
// additional MCP Content blocks to tool results.
func TestResponseEnricherAppends(t *testing.T) {
	t.Parallel()

	impl := &settingsCRUD{}
	cookie := "the-secret"
	impl.stored.Store(&configpb.Settings{CookieSecret: &cookie})

	enricher := func(_ context.Context, _ protoreflect.MethodDescriptor, _ proto.Message) []mcp.Content {
		return []mcp.Content{&mcp.TextContent{Text: "Edit in admin UI: https://example.com/canonical"}}
	}
	url := newTestServer(t, impl, configapi.WithResponseEnricher(enricher))
	session := connectMCP(t, url)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resp, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_settings",
		Arguments: map[string]any{"id": "any"},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError, "%+v", resp.Content)

	require.GreaterOrEqual(t, len(resp.Content), 2, "expected enricher block appended")
	last := resp.Content[len(resp.Content)-1].(*mcp.TextContent).Text
	assert.Contains(t, last, "https://example.com/canonical")
}
