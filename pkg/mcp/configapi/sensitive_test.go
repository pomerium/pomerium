package configapi_test

import (
	"context"
	"errors"
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
