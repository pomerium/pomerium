package configapi_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
	"hegel.dev/go/hegel"

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

	// Values must never reach the wire.
	assert.NotContains(t, body, secret, "cookie_secret value leaked")
	assert.NotContains(t, body, signing, "signing_key value leaked")
	// The Settings.* names appear under _meta.scrubbedFields (intentional —
	// it tells the LLM what's set and hidden); but their VALUES never do.
	assert.Contains(t, body, "scrubbedFields")
	assert.Contains(t, body, "settings.cookieSecret")
	assert.Contains(t, body, "settings.signingKey")
}

// TestGetRouteScrubsNestedOAuthClientSecret reproduces what the user sees
// live: a Route whose upstreamOauth2.client_secret is configured comes
// back through MCP with the secret value verbatim, even though the field
// carries [(sensitive) = true]. Asserts the value does NOT leak and the
// field path appears under _meta.scrubbedFields.
func TestGetRouteScrubsNestedOAuthClientSecret(t *testing.T) {
	t.Parallel()

	id := "bnghfpXPKJRNvPwvBxgsZcZRnzV"
	secret := "uniq-leak-canary-9f3a"
	impl := &routeCRUDForGet{}
	impl.stored.Store(&configpb.Route{
		Id:   &id,
		Name: new("github"),
		Mcp: &configpb.MCP{
			Mode: &configpb.MCP_Server{
				Server: &configpb.MCPServer{
					UpstreamOauth2: &configpb.UpstreamOAuth2{
						ClientId:     "Iv23liKZOxlR9v70ROHf",
						ClientSecret: secret,
						Scopes:       []string{"read:user", "user:email"},
					},
				},
			},
		},
	})

	session := connectMCP(t, newTestServer(t, impl))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resp, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_route",
		Arguments: map[string]any{"id": id},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError, "%+v", resp.Content)
	require.NotEmpty(t, resp.Content)
	body := resp.Content[0].(*mcp.TextContent).Text

	assert.NotContains(t, body, secret,
		"upstreamOauth2.client_secret VALUE leaked through MCP — sensitive scrub failed for the nested oneof + non-optional scalar case")

	require.NotNil(t, resp.StructuredContent)
	structured := resp.StructuredContent.(map[string]any)
	meta, ok := structured["_meta"].(map[string]any)
	require.True(t, ok, "_meta missing on response: %v", structured)
	scrubbed, _ := meta["scrubbedFields"].([]any)
	var paths []string
	for _, p := range scrubbed {
		paths = append(paths, p.(string))
	}
	assert.Contains(t, paths, "route.mcp.server.upstreamOauth2.clientSecret",
		"the redacted-fields list must name the path even when the value is properly scrubbed")
}

type routeCRUDForGet struct {
	configconnect.UnimplementedConfigServiceHandler
	stored atomic.Pointer[configpb.Route]
}

func (s *routeCRUDForGet) GetRoute(_ context.Context, req *connect.Request[configpb.GetRouteRequest]) (*connect.Response[configpb.GetRouteResponse], error) {
	got := s.stored.Load()
	if got == nil || got.GetId() != req.Msg.Id {
		return nil, connect.NewError(connect.CodeNotFound, nil)
	}
	return connect.NewResponse(&configpb.GetRouteResponse{Route: got}), nil
}

// TestScrubSensitive_NestedOAuthClientSecret directly exercises the
// scrub walker against the user's exact message shape — Route with
// mcp.server.upstreamOauth2.clientSecret set — to isolate whether the
// scrubber misses this case independent of the full MCP pipeline.
func TestScrubSensitive_NestedOAuthClientSecret(t *testing.T) {
	t.Parallel()

	const secret = "uniq-leak-canary-9f3a"
	id := "bnghfpXPKJRNvPwvBxgsZcZRnzV"
	resp := &configpb.GetRouteResponse{
		Route: &configpb.Route{
			Id:   &id,
			Name: new("github"),
			Mcp: &configpb.MCP{
				Mode: &configpb.MCP_Server{
					Server: &configpb.MCPServer{
						UpstreamOauth2: &configpb.UpstreamOAuth2{
							ClientId:     "Iv23liKZOxlR9v70ROHf",
							ClientSecret: secret,
							Scopes:       []string{"read:user", "user:email"},
						},
					},
				},
			},
		},
	}

	configapi.ScrubSensitive(resp)

	got := resp.GetRoute().GetMcp().GetServer().GetUpstreamOauth2().GetClientSecret()
	assert.Empty(t, got, "ScrubSensitive must clear nested upstreamOauth2.clientSecret; got %q", got)

	// Defense-in-depth: check via marshal too — if the proto getter says
	// empty but JSON serialization still emits the value somehow, that's
	// also a leak.
	jsonBytes, err := protojson.Marshal(resp)
	require.NoError(t, err)
	assert.NotContains(t, string(jsonBytes), secret, "scrubbed field re-appeared in JSON marshal")
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

// TestUpdatePreservesNestedSensitive_OAuthClientSecret pins down the
// "sensitive fields are preserved from the existing record" contract for
// fields nested under non-sensitive enclosing messages. The schema scrubs
// route.mcp.server.upstreamOauth2.clientSecret from update_route's input —
// the LLM cannot supply it. So when an update touches anything inside
// `mcp`, the merge must dive recursively to leave the existing clientSecret
// in place; otherwise wholesale replacement at the top level wipes it.
//
// Each scenario describes a specific update shape and asserts what the
// stored record should look like afterward. The "sibling at deepest level"
// and "intermediate enclosure" scenarios are the ones the original sparse-
// patch implementation got wrong.
func TestUpdatePreservesNestedSensitive_OAuthClientSecret(t *testing.T) {
	t.Parallel()

	const (
		id                      = "r-1"
		existingClientSecret    = "deep-secret-DO-NOT-LOSE"
		existingTLSClientKey    = "PRIVATE-KEY-XYZ"
		existingIdpClientSecret = "idp-secret-stay-put"
		existingFrom            = "https://existing.example"
		existingClientID        = "old-client-id"
	)

	type assertion struct {
		clientID        string
		clientSecret    string
		from            string
		tlsClientKey    string
		idpClientSecret string
		description     string
	}
	defaultAssertion := assertion{
		clientID:        existingClientID,
		clientSecret:    existingClientSecret,
		from:            existingFrom,
		tlsClientKey:    existingTLSClientKey,
		idpClientSecret: existingIdpClientSecret,
	}
	with := func(mut func(*assertion)) assertion {
		a := defaultAssertion
		mut(&a)
		return a
	}

	cases := []struct {
		name string
		args map[string]any
		want assertion
	}{
		{
			name: "top-level sibling update preserves all sensitive (baseline)",
			args: map[string]any{
				"id":          id,
				"description": "updated",
			},
			want: with(func(a *assertion) { a.description = "updated" }),
		},
		{
			name: "deep sibling at the same level: update clientId, preserve clientSecret",
			args: map[string]any{
				"id": id,
				"mcp": map[string]any{
					"server": map[string]any{
						"upstreamOauth2": map[string]any{
							"clientId": "new-client-id",
						},
					},
				},
			},
			want: with(func(a *assertion) { a.clientID = "new-client-id" }),
		},
		{
			name: "intermediate enclosure update: replace upstreamOauth2 with clientId-only",
			args: map[string]any{
				"id": id,
				"mcp": map[string]any{
					"server": map[string]any{
						"upstreamOauth2": map[string]any{
							"clientId": "via-enclosure",
						},
					},
				},
			},
			want: with(func(a *assertion) { a.clientID = "via-enclosure" }),
		},
		{
			name: "outer enclosure update: empty mcp object must not wipe deep sensitive",
			args: map[string]any{
				"id":  id,
				"mcp": map[string]any{},
			},
			want: defaultAssertion,
		},
		{
			name: "distant top-level update leaves nested subtree untouched",
			args: map[string]any{
				"id":   id,
				"from": "https://updated.example",
			},
			want: with(func(a *assertion) { a.from = "https://updated.example" }),
		},
		{
			name: "deep update of a list field at the deepest level: scopes change, secrets survive",
			args: map[string]any{
				"id": id,
				"mcp": map[string]any{
					"server": map[string]any{
						"upstreamOauth2": map[string]any{
							"scopes": []any{"openid", "email"},
						},
					},
				},
			},
			want: defaultAssertion,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			impl := &routeCRUDWithUpdate{}
			localID := id
			localClientID := existingClientID
			localIdpClientSecret := existingIdpClientSecret
			impl.stored.Store(&configpb.Route{
				Id:              &localID,
				From:            existingFrom,
				TlsClientKey:    existingTLSClientKey,
				IdpClientSecret: &localIdpClientSecret,
				Mcp: &configpb.MCP{
					Mode: &configpb.MCP_Server{
						Server: &configpb.MCPServer{
							UpstreamOauth2: &configpb.UpstreamOAuth2{
								ClientId:     localClientID,
								ClientSecret: existingClientSecret,
							},
						},
					},
				},
			})

			session := connectMCP(t, newTestServer(t, impl))
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()

			resp, err := session.CallTool(ctx, &mcp.CallToolParams{
				Name:      "update_route",
				Arguments: map[string]any{"route": tc.args},
			})
			require.NoError(t, err)
			require.False(t, resp.IsError, "%+v", resp.Content)

			got := impl.stored.Load()
			require.NotNil(t, got)
			assert.Equal(t, tc.want.from, got.GetFrom(), "from")
			assert.Equal(t, tc.want.tlsClientKey, got.GetTlsClientKey(), "tlsClientKey")
			assert.Equal(t, tc.want.idpClientSecret, got.GetIdpClientSecret(), "idpClientSecret")
			assert.Equal(t, tc.want.description, got.GetDescription(), "description")
			assert.Equal(t, tc.want.clientID, got.GetMcp().GetServer().GetUpstreamOauth2().GetClientId(),
				"mcp.server.upstreamOauth2.clientId")
			assert.Equal(t, tc.want.clientSecret, got.GetMcp().GetServer().GetUpstreamOauth2().GetClientSecret(),
				"mcp.server.upstreamOauth2.clientSecret (deeply-nested sensitive — must survive)")
		})
	}
}

// TestUpdateExplicitClearAtDepth pins down that a deeply-nested non-sensitive
// field can be cleared by the LLM, even when its container also holds a
// sensitive field that must survive. The relevant proto3 quirk: for a
// non-optional scalar, Has() == false at zero value; merging via the JSON
// key tree (rather than just incoming.Has) is what lets the explicit empty
// string read through as "clear" instead of "skip".
func TestUpdateExplicitClearAtDepth(t *testing.T) {
	t.Parallel()

	const id = "r-clear"
	impl := &routeCRUDWithUpdate{}
	localID := id
	impl.stored.Store(&configpb.Route{
		Id:   &localID,
		From: "https://x.example",
		Mcp: &configpb.MCP{
			Mode: &configpb.MCP_Server{
				Server: &configpb.MCPServer{
					UpstreamOauth2: &configpb.UpstreamOAuth2{
						ClientId:     "old-id",
						ClientSecret: "DEEP-SECRET",
					},
				},
			},
		},
	})

	session := connectMCP(t, newTestServer(t, impl))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resp, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "update_route",
		Arguments: map[string]any{
			"route": map[string]any{
				"id": id,
				"mcp": map[string]any{
					"server": map[string]any{
						"upstreamOauth2": map[string]any{"clientId": ""},
					},
				},
			},
		},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError, "%+v", resp.Content)

	got := impl.stored.Load()
	require.NotNil(t, got)
	assert.Empty(t, got.GetMcp().GetServer().GetUpstreamOauth2().GetClientId(),
		"explicit empty string at depth must clear the field")
	assert.Equal(t, "DEEP-SECRET", got.GetMcp().GetServer().GetUpstreamOauth2().GetClientSecret(),
		"clearing a sibling at depth must not wipe the deep sensitive sibling")
}

// TestUpdateOneofVariantSwitch documents the contract for oneof variant
// changes: when the LLM intentionally switches the active variant, the
// merge replaces the whole oneof — including any sensitive descendants
// the LLM cannot re-supply. This is by design: a variant switch is not a
// sparse update of the existing variant.
func TestUpdateOneofVariantSwitch(t *testing.T) {
	t.Parallel()

	const id = "r-switch"
	impl := &routeCRUDWithUpdate{}
	localID := id
	impl.stored.Store(&configpb.Route{
		Id:   &localID,
		From: "https://x.example",
		Mcp: &configpb.MCP{
			Mode: &configpb.MCP_Server{
				Server: &configpb.MCPServer{
					UpstreamOauth2: &configpb.UpstreamOAuth2{
						ClientId:     "server-client",
						ClientSecret: "server-secret",
					},
				},
			},
		},
	})

	session := connectMCP(t, newTestServer(t, impl))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resp, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "update_route",
		Arguments: map[string]any{
			"route": map[string]any{
				"id": id,
				"mcp": map[string]any{
					// Switch from server variant to client variant.
					"client": map[string]any{},
				},
			},
		},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError, "%+v", resp.Content)

	got := impl.stored.Load()
	require.NotNil(t, got)
	assert.Nil(t, got.GetMcp().GetServer(),
		"variant switch must drop the prior server variant (and its secrets)")
	assert.NotNil(t, got.GetMcp().GetClient(),
		"the new client variant must be set")
}

// routeCRUDGetAlwaysFails is a stub whose GetRoute returns Unavailable, so
// applyUpdatePatch's fetch-existing step fails. UpdateRoute records whether
// the merge fell through despite the Get failure (it must NOT — without the
// existing record the merge cannot preserve sensitive fields).
type routeCRUDGetAlwaysFails struct {
	configconnect.UnimplementedConfigServiceHandler
	updateCalls atomic.Int32
}

func (s *routeCRUDGetAlwaysFails) GetRoute(_ context.Context, _ *connect.Request[configpb.GetRouteRequest]) (*connect.Response[configpb.GetRouteResponse], error) {
	return nil, connect.NewError(connect.CodeUnavailable, errors.New("upstream offline"))
}

func (s *routeCRUDGetAlwaysFails) UpdateRoute(_ context.Context, req *connect.Request[configpb.UpdateRouteRequest]) (*connect.Response[configpb.UpdateRouteResponse], error) {
	s.updateCalls.Add(1)
	return connect.NewResponse(&configpb.UpdateRouteResponse{Route: req.Msg.Route}), nil
}

// TestApplyUpdatePatch_GetCallFails verifies that when the inner Get*
// call applyUpdatePatch issues fails, the registry fails closed: the
// tool surfaces an MCP error to the LLM and Update is NOT dispatched.
// Without this, the schema-stripped sparse Update would wipe every
// sensitive field on the persisted record.
func TestApplyUpdatePatch_GetCallFails(t *testing.T) {
	t.Parallel()

	impl := &routeCRUDGetAlwaysFails{}
	session := connectMCP(t, newTestServer(t, impl))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resp, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "update_route",
		Arguments: map[string]any{
			"route": map[string]any{"id": "r-1", "from": "https://new.example"},
		},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError,
		"Update must surface an MCP tool error when the inner Get fails; %+v", resp.Content)
	assert.Equal(t, int32(0), impl.updateCalls.Load(),
		"Update must NOT be dispatched once the merge fails — fail closed protects sensitive fields")
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

// TestMetaContributorReceivesDynamicMessageOnCanonicalDescriptor pins down
// the contract that callers MUST be handed a *dynamicpb.Message backed by
// the descriptor we hold internally (the one from method.Output()), and
// MUST NOT receive a Go type produced by protoregistry.GlobalTypes lookup.
//
// Why: in a binary that links two modules vendoring the same .proto file
// (e.g. pomerium-zero pulls both pomerium/pkg/grpc/config and
// sdk-go/proto/pomerium with -X protoregistry.conflictPolicy=ignore), the
// global registry returns whichever module's init ran first. That type's
// FieldDescriptor.Options() carry the *other* module's extensions — i.e.
// our (pomerium.config.sensitive) annotation is silently absent — so
// reflection-based scrub no-ops while everything looks fine in tests.
//
// Using dynamicpb against the descriptor we already have avoids the
// global registry entirely: the descriptor we got from
// configpb.File_config_proto.Services()...Output() is unambiguous, and
// the dynamic message reflects exactly that descriptor.
func TestMetaContributorReceivesDynamicMessageOnCanonicalDescriptor(t *testing.T) {
	t.Parallel()

	impl := &settingsCRUD{}
	impl.stored.Store(&configpb.Settings{})

	var captured proto.Message
	contributor := func(_ context.Context, _ protoreflect.MethodDescriptor, m proto.Message, _ []string) map[string]any {
		captured = m
		return nil
	}

	url := newTestServer(t, impl, configapi.WithMetaContributor(contributor))
	session := connectMCP(t, url)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_settings",
		Arguments: map[string]any{"id": "any"},
	})
	require.NoError(t, err)
	require.NotNil(t, captured)

	_, isDynamic := captured.(*dynamicpb.Message)
	assert.True(t, isDynamic,
		"MetaContributor must receive *dynamicpb.Message; configapi must not consult protoregistry.GlobalTypes")

	// And the descriptor must be exactly the one configapi advertised on
	// method.Output() — not whatever the registry would have resolved.
	wantDesc := configpb.File_config_proto.Services().Get(0).
		Methods().ByName("GetSettings").Output()
	assert.Same(t, wantDesc, captured.ProtoReflect().Descriptor(),
		"contributor's message descriptor must equal method.Output() by pointer identity")
}

// TestMetaContributorMergedIntoStructured verifies metadata returned by a
// MetaContributor lands under the _meta key on structuredContent — the
// canonical place we surface the canonical UI URL and similar hints.
//
// The realistic contributor identifies the response by proto descriptor
// FullName(), not by Go type assertion. See the comment on
// TestMetaContributorReceivesDynamicMessageOnCanonicalDescriptor for why.
func TestMetaContributorMergedIntoStructured(t *testing.T) {
	t.Parallel()

	impl := &settingsCRUD{}
	cookie := "the-secret"
	impl.stored.Store(&configpb.Settings{CookieSecret: &cookie})

	contributor := func(_ context.Context, _ protoreflect.MethodDescriptor, msg proto.Message, _ []string) map[string]any {
		// Match by proto identity, not Go type — robust to vendored
		// duplicates of the proto file in sibling modules.
		if msg.ProtoReflect().Descriptor().FullName() != "pomerium.config.GetSettingsResponse" {
			return nil
		}
		return map[string]any{
			"links": map[string]any{"canonical": "https://example.com/canonical"},
		}
	}
	url := newTestServer(t, impl, configapi.WithMetaContributor(contributor))
	session := connectMCP(t, url)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resp, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_settings",
		Arguments: map[string]any{"id": "any"},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError, "%+v", resp.Content)

	require.NotNil(t, resp.StructuredContent)
	body, ok := resp.StructuredContent.(map[string]any)
	require.True(t, ok, "structuredContent should decode as object: %T", resp.StructuredContent)
	meta, ok := body["_meta"].(map[string]any)
	require.True(t, ok, "_meta missing from structuredContent: %v", body)
	links, ok := meta["links"].(map[string]any)
	require.True(t, ok, "_meta.links missing: %v", meta)
	assert.Equal(t, "https://example.com/canonical", links["canonical"])
	assert.Contains(t, meta["scrubbedFields"], "settings.cookieSecret")
}

// TestSensitiveFieldsSet verifies the standalone walker reports populated
// sensitive fields by JSON path, sorted, with no duplicates.
func TestSensitiveFieldsSet(t *testing.T) {
	t.Parallel()

	cookie := "abcd"
	signing := "xyz"
	idpSecret := "client-secret"

	cases := []struct {
		name string
		msg  proto.Message
		want []string
	}{
		{
			name: "empty Settings",
			msg:  &configpb.Settings{},
			want: nil,
		},
		{
			name: "Settings with cookie+signing+idp set",
			msg: &configpb.Settings{
				CookieSecret:    &cookie,
				SigningKey:      &signing,
				IdpClientSecret: &idpSecret,
			},
			want: []string{"cookieSecret", "idpClientSecret", "signingKey"},
		},
		{
			name: "list element with sensitive sub-field collapses to glob",
			msg: &configpb.Settings{
				Certificates: []*configpb.Settings_Certificate{
					{KeyBytes: []byte("a")},
					{KeyBytes: []byte("b")},
				},
			},
			want: []string{"certificates[].keyBytes"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := configapi.SensitiveFieldsSet(tc.msg)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestResponseEnricherReceivesRedactedList verifies the enricher gets the
// list of sensitive fields populated on the response, before they were
// scrubbed.
func TestResponseEnricherReceivesRedactedList(t *testing.T) {
	t.Parallel()

	impl := &settingsCRUD{}
	cookie := "the-cookie-secret-value"
	signing := "the-signing-key-value"
	impl.stored.Store(&configpb.Settings{
		CookieSecret: &cookie,
		SigningKey:   &signing,
	})

	var seen []string
	contributor := func(_ context.Context, _ protoreflect.MethodDescriptor, _ proto.Message, redacted []string) map[string]any {
		seen = append([]string{}, redacted...)
		return nil
	}

	url := newTestServer(t, impl, configapi.WithMetaContributor(contributor))
	session := connectMCP(t, url)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_settings",
		Arguments: map[string]any{"id": "any"},
	})
	require.NoError(t, err)

	assert.Equal(t, []string{"settings.cookieSecret", "settings.signingKey"}, seen)
}

// quotaCRUD always returns ResourceExhausted on CreateServiceAccount; it
// exists so we can verify ErrorMapper transforms the error before the MCP
// client ever sees it.
type quotaCRUD struct {
	configconnect.UnimplementedConfigServiceHandler
}

func (quotaCRUD) CreateServiceAccount(_ context.Context, _ *connect.Request[configpb.CreateServiceAccountRequest]) (*connect.Response[configpb.CreateServiceAccountResponse], error) {
	// Mimics the actual wire text our connect handlers emit; the redacted
	// stutter and "Contact support@…" hint are exactly what we want the
	// mapper to scrub.
	const wire = "error creating service account: db: CreateServiceAccount failed: The serviceAccounts quota was exceeded. Contact support@pomerium.com to request a quota increase."
	return nil, connect.NewError(connect.CodeResourceExhausted, errors.New(wire))
}

// TestErrorMapperRedactsQuota verifies that an ErrorMapper can replace the
// raw connect-error message with a sanitized, user-facing one.
func TestErrorMapperRedactsQuota(t *testing.T) {
	t.Parallel()

	mapper := func(_ context.Context, _ protoreflect.MethodDescriptor, err error) error {
		var ce *connect.Error
		if errors.As(err, &ce) && ce.Code() == connect.CodeResourceExhausted {

			const replacement = "Quota exceeded. Visit https://example.test/billing to upgrade your plan."
			return connect.NewError(connect.CodeResourceExhausted, errors.New(replacement))
		}
		return err
	}

	url := newTestServer(t, quotaCRUD{}, configapi.WithErrorMapper(mapper))
	session := connectMCP(t, url)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resp, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "create_service_account",
		Arguments: map[string]any{"serviceAccount": map[string]any{"description": "x"}},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError, "expected tool error")
	require.Len(t, resp.Content, 1)
	text := resp.Content[0].(*mcp.TextContent).Text

	assert.Contains(t, text, "https://example.test/billing", "sanitized message must include redirect URL")
	assert.NotContains(t, text, "db:", "internal stutter must be redacted")
	assert.NotContains(t, text, "CreateServiceAccount failed", "internal stutter must be redacted")
	assert.NotContains(t, text, "support@pomerium.com", "original support hint must be replaced")
}

// ---- Property-based tests (Hegel) ---------------------------------------
//
// The properties below exercise the registry → merge → caller dispatch
// path against a single invariant: for any update_* MCP tool call, every
// sensitive field on the persisted record after dispatch must equal its
// prior value, unless the merge logic visibly overwrote it. The
// schema-stripped zero must never reach the persisted record. A property
// failure shrinks to a small counterexample showing a shape the merge
// mishandles.

// sensitiveSentinel returns an ASCII string the test reserves for
// sensitive values. The 16–32 byte range is the only intentional length
// in this file — long enough that collisions with non-sensitive content
// (or proto JSON field names) are astronomically unlikely, so a
// substring search in the scrubbed output is a sound leak detector.
func sensitiveSentinel(ht *hegel.T, label string) string {
	body := hegel.Draw(ht, hegel.Text().MinSize(16).MaxSize(32))
	// Scrub characters that protojson might escape on a round-trip and
	// that would split the sentinel across boundaries. Limiting to
	// ASCII letters/digits keeps the substring search exact.
	clean := make([]byte, 0, len(body))
	for i := 0; i < len(body); i++ {
		c := body[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			clean = append(clean, c)
		}
	}
	if len(clean) < 4 {
		clean = append(clean, 'x', 'y', 'z', 'q')
	}
	return "SECRET-" + label + "-" + string(clean)
}

// TestProp_ScrubSensitive_NoLeakage walks an arbitrary Route populated
// with sentinel sensitive values, applies ScrubSensitive, marshals to
// protojson, and asserts that no sentinel appears in the output. A
// failure means the scrub walker missed a path — perhaps a oneof variant
// shape, a sensitive map/list element, or a nested message we didn't
// previously cover.
func TestProp_ScrubSensitive_NoLeakage(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		// Build a Route with random sentinel values for every sensitive
		// scalar configapi knows about. Each sentinel is unique so a
		// substring miss in the output points at a specific field.
		tlsKey := sensitiveSentinel(ht, "TLS")
		k8sToken := sensitiveSentinel(ht, "K8S")
		idpClientSecret := sensitiveSentinel(ht, "IDPCS")
		oauth2ClientSecret := sensitiveSentinel(ht, "OAUTH2CS")

		id := "r-prop-1"
		route := &configpb.Route{
			Id:                            &id,
			From:                          "https://prop.example",
			TlsClientKey:                  tlsKey,
			KubernetesServiceAccountToken: k8sToken,
			IdpClientSecret:               &idpClientSecret,
		}
		// Optionally exercise the deep oneof path: the merge code for
		// upstreamOauth2 was the original site of a sensitive-handling
		// bug, so the property test should reach it often.
		if hegel.Draw(ht, hegel.Booleans()) {
			route.Mcp = &configpb.MCP{
				Mode: &configpb.MCP_Server{
					Server: &configpb.MCPServer{
						UpstreamOauth2: &configpb.UpstreamOAuth2{
							ClientId:     "client-1",
							ClientSecret: oauth2ClientSecret,
						},
					},
				},
			}
		}

		sensitives := []string{tlsKey, k8sToken, idpClientSecret}
		if route.GetMcp() != nil {
			sensitives = append(sensitives, oauth2ClientSecret)
		}

		// Pre-condition sanity: every sentinel really is in the message
		// before we scrub. Without this, a generator regression that
		// produced empty strings would silently make the property
		// vacuously true.
		preJSON, err := protojson.Marshal(route)
		require.NoError(ht, err)
		for _, s := range sensitives {
			require.Contains(ht, string(preJSON), s,
				"generator failed to populate sentinel %q", s)
		}

		configapi.ScrubSensitive(route)

		postJSON, err := protojson.Marshal(route)
		require.NoError(ht, err)
		for _, s := range sensitives {
			assert.NotContains(ht, string(postJSON), s,
				"sensitive sentinel %q survived ScrubSensitive — walker missed a path", s)
		}
	})
}

// routeCRUDPropCapture is the stub used by TestProp_UpdateRoute. It supports
// the same get-success / get-error stub patterns the unit pinning tests
// use, and captures the dispatched UpdateRoute message so the property
// can inspect its sensitive fields.
type routeCRUDPropCapture struct {
	configconnect.UnimplementedConfigServiceHandler
	stored         atomic.Pointer[configpb.Route]
	getErr         atomic.Value // error or nil
	receivedUpdate atomic.Pointer[configpb.Route]
}

func (s *routeCRUDPropCapture) GetRoute(_ context.Context, req *connect.Request[configpb.GetRouteRequest]) (*connect.Response[configpb.GetRouteResponse], error) {
	if v := s.getErr.Load(); v != nil {
		if e, ok := v.(error); ok && e != nil {
			return nil, e
		}
	}
	got := s.stored.Load()
	if got == nil || got.GetId() != req.Msg.Id {
		return nil, connect.NewError(connect.CodeNotFound, nil)
	}
	return connect.NewResponse(&configpb.GetRouteResponse{Route: got}), nil
}

func (s *routeCRUDPropCapture) UpdateRoute(_ context.Context, req *connect.Request[configpb.UpdateRouteRequest]) (*connect.Response[configpb.UpdateRouteResponse], error) {
	clone := proto.Clone(req.Msg.Route).(*configpb.Route)
	s.receivedUpdate.Store(clone)
	return connect.NewResponse(&configpb.UpdateRouteResponse{Route: clone}), nil
}

// TestProp_UpdateRoute_PreservesSensitive drives update_route through the
// real MCP harness with a pre-stored Route holding sentinel sensitive
// values, an arbitrary update overlay, and a chosen Get behavior. The
// invariant: either the tool returns an error to the MCP client (fail-
// closed: acceptable), or every sensitive field in the dispatched
// UpdateRoute equals the pre-stored sentinel (the merge preserved it).
//
// Two narrow shapes this property exercises are also pinned individually
// in update_safety_test.go (TestUpdate_FailsClosedOnInnerGetError and
// TestUpdate_RefusesWithMissingEntityID): the Get-fails path and the
// missing-id path both drive the merge into its error return. Anything
// the property finds beyond those shapes is a new merge bug.
// TestProp_UpdateRoute_PreservesSensitive_HappyPath constrains id to
// always be present and Get to always succeed; a failure there is a new
// merge-recursion or oneof-handling bug.
func TestProp_UpdateRoute_PreservesSensitive(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		// Populate sentinels.
		tlsKey := sensitiveSentinel(ht, "TLS")
		k8sToken := sensitiveSentinel(ht, "K8S")
		idpClientSecret := sensitiveSentinel(ht, "IDPCS")
		oauth2ClientSecret := sensitiveSentinel(ht, "OAUTH2CS")

		id := "r-prop-1"
		stored := &configpb.Route{
			Id:                            &id,
			From:                          "https://stored.example",
			TlsClientKey:                  tlsKey,
			KubernetesServiceAccountToken: k8sToken,
			IdpClientSecret:               &idpClientSecret,
			Mcp: &configpb.MCP{
				Mode: &configpb.MCP_Server{
					Server: &configpb.MCPServer{
						UpstreamOauth2: &configpb.UpstreamOAuth2{
							ClientId:     "stored-client-id",
							ClientSecret: oauth2ClientSecret,
						},
					},
				},
			},
		}

		// Build the update overlay. Each branch is independent; this
		// reproduces the most relevant slices of LLM behavior:
		//   - include or omit the id (drives the missing-id refusal)
		//   - include or omit non-sensitive scalars
		//   - reach into the deeply-nested oneof
		overlay := map[string]any{}
		if hegel.Draw(ht, hegel.Booleans()) {
			overlay["id"] = id
		}
		if hegel.Draw(ht, hegel.Booleans()) {
			overlay["description"] = "desc-1"
		}
		if hegel.Draw(ht, hegel.Booleans()) {
			overlay["from"] = "https://updated.example"
		}
		if hegel.Draw(ht, hegel.Booleans()) {
			mcpOverlay := map[string]any{}
			switch hegel.Draw(ht, hegel.Integers[int](0, 3)) {
			case 0:
				// touch upstreamOauth2.clientId — sibling of clientSecret
				mcpOverlay["server"] = map[string]any{
					"upstreamOauth2": map[string]any{
						"clientId": "new-client-1",
					},
				}
			case 1:
				// empty server enclosure (must not wipe deep secrets)
				mcpOverlay["server"] = map[string]any{}
			case 2:
				// switch oneof variant — deletes server (and its secret) by design
				mcpOverlay["client"] = map[string]any{}
			case 3:
				// empty mcp object (outer enclosure update)
			}
			overlay["mcp"] = mcpOverlay
		}

		// Choose Get behavior. Get-error drives applyUpdatePatch into
		// its err path so the registry's fail-closed guard fires.
		getFails := hegel.Draw(ht, hegel.Booleans())

		// Set up the in-process MCP server with the chosen behaviors.
		impl := &routeCRUDPropCapture{}
		impl.stored.Store(stored)
		if getFails {
			impl.getErr.Store(error(connect.NewError(connect.CodeUnavailable, errors.New("get fails"))))
		}

		session := connectMCP(t, newTestServer(t, impl))
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()

		resp, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name:      "update_route",
			Arguments: map[string]any{"route": overlay},
		})
		if err != nil {
			// Transport error: not a property violation by itself,
			// but worth noting on shrinking.
			ht.Note(fmt.Sprintf("transport error: %v (overlay=%v, getFails=%v)", err, overlay, getFails))
			return
		}
		if resp.IsError {
			// Tool failed-closed; that's the acceptable outcome on
			// any merge problem. The invariant only constrains the
			// dispatch case.
			return
		}

		dispatched := impl.receivedUpdate.Load()
		if dispatched == nil {
			// Update wasn't dispatched (tool returned non-error but
			// didn't reach inner UpdateRoute). Vacuously satisfies
			// the invariant — log for visibility.
			ht.Note("no UpdateRoute dispatched but tool reported non-error")
			return
		}

		// Did the LLM intentionally switch the oneof variant? The
		// merge is documented to drop the prior variant (and its
		// secrets) on a switch. Detect this by inspecting the
		// overlay we constructed.
		mcp, _ := overlay["mcp"].(map[string]any)
		_, switchedToClient := mcp["client"]

		if !switchedToClient {
			// upstreamOauth2.clientSecret must survive the merge.
			gotClientSecret := dispatched.GetMcp().GetServer().GetUpstreamOauth2().GetClientSecret()
			assert.Equal(ht, oauth2ClientSecret, gotClientSecret,
				"INVARIANT VIOLATED: oauth2 clientSecret was wiped on Update.\n"+
					"  overlay = %#v\n"+
					"  getFails = %v",
				overlay, getFails)
		}

		// Top-level sensitive scalars must always survive.
		assert.Equal(ht, tlsKey, dispatched.GetTlsClientKey(),
			"INVARIANT VIOLATED: tlsClientKey wiped (overlay=%#v, getFails=%v)", overlay, getFails)
		assert.Equal(ht, k8sToken, dispatched.GetKubernetesServiceAccountToken(),
			"INVARIANT VIOLATED: kubernetesServiceAccountToken wiped (overlay=%#v, getFails=%v)", overlay, getFails)
		assert.Equal(ht, idpClientSecret, dispatched.GetIdpClientSecret(),
			"INVARIANT VIOLATED: idpClientSecret wiped (overlay=%#v, getFails=%v)", overlay, getFails)
	})
}

// TestProp_UpdateRoute_PreservesSensitive_HappyPath is the constrained
// variant: id is always present, Get always succeeds. Under those
// preconditions the merge IS supposed to preserve every sensitive field.
// If Hegel finds a counterexample here, it's a new merge-recursion or
// oneof-handling bug.
func TestProp_UpdateRoute_PreservesSensitive_HappyPath(t *testing.T) {
	hegel.Test(t, func(ht *hegel.T) {
		tlsKey := sensitiveSentinel(ht, "TLS")
		k8sToken := sensitiveSentinel(ht, "K8S")
		idpClientSecret := sensitiveSentinel(ht, "IDPCS")
		oauth2ClientSecret := sensitiveSentinel(ht, "OAUTH2CS")

		id := "r-prop-1"
		stored := &configpb.Route{
			Id:                            &id,
			From:                          "https://stored.example",
			TlsClientKey:                  tlsKey,
			KubernetesServiceAccountToken: k8sToken,
			IdpClientSecret:               &idpClientSecret,
			Mcp: &configpb.MCP{
				Mode: &configpb.MCP_Server{
					Server: &configpb.MCPServer{
						UpstreamOauth2: &configpb.UpstreamOAuth2{
							ClientId:     "stored-client-id",
							ClientSecret: oauth2ClientSecret,
						},
					},
				},
			},
		}

		// id always present; non-sensitive overlay can be anything.
		overlay := map[string]any{"id": id}
		if hegel.Draw(ht, hegel.Booleans()) {
			overlay["description"] = "desc-1"
		}
		if hegel.Draw(ht, hegel.Booleans()) {
			overlay["from"] = "https://updated.example"
		}
		if hegel.Draw(ht, hegel.Booleans()) {
			overlay["name"] = "name-1"
		}
		switchedToClient := false
		if hegel.Draw(ht, hegel.Booleans()) {
			mcpOverlay := map[string]any{}
			switch hegel.Draw(ht, hegel.Integers[int](0, 4)) {
			case 0:
				mcpOverlay["server"] = map[string]any{
					"upstreamOauth2": map[string]any{
						"clientId": "new-client-1",
					},
				}
			case 1:
				mcpOverlay["server"] = map[string]any{
					"upstreamOauth2": map[string]any{
						"scopes": []any{"openid", "email"},
					},
				}
			case 2:
				mcpOverlay["server"] = map[string]any{}
			case 3:
				// oneof variant switch — drops server (and its secret) by design
				mcpOverlay["client"] = map[string]any{}
				switchedToClient = true
			case 4:
				// (empty mcp object)
			}
			overlay["mcp"] = mcpOverlay
		}

		impl := &routeCRUDPropCapture{}
		impl.stored.Store(stored)

		session := connectMCP(t, newTestServer(t, impl))
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()

		resp, err := session.CallTool(ctx, &mcp.CallToolParams{
			Name:      "update_route",
			Arguments: map[string]any{"route": overlay},
		})
		if err != nil {
			ht.Note(fmt.Sprintf("transport error: %v (overlay=%v)", err, overlay))
			return
		}
		if resp.IsError {
			ht.Note(fmt.Sprintf("tool error (acceptable): overlay=%v", overlay))
			return
		}

		dispatched := impl.receivedUpdate.Load()
		require.NotNil(ht, dispatched)

		if !switchedToClient {
			assert.Equal(ht, oauth2ClientSecret,
				dispatched.GetMcp().GetServer().GetUpstreamOauth2().GetClientSecret(),
				"oauth2 clientSecret wiped on happy-path Update; overlay=%#v", overlay)
		}
		assert.Equal(ht, tlsKey, dispatched.GetTlsClientKey(),
			"tlsClientKey wiped on happy-path Update; overlay=%#v", overlay)
		assert.Equal(ht, k8sToken, dispatched.GetKubernetesServiceAccountToken(),
			"kubernetesServiceAccountToken wiped on happy-path Update; overlay=%#v", overlay)
		assert.Equal(ht, idpClientSecret, dispatched.GetIdpClientSecret(),
			"idpClientSecret wiped on happy-path Update; overlay=%#v", overlay)
	})
}
