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
	"google.golang.org/protobuf/proto"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/config/configconnect"
)

// routeCRUDCapture captures the UpdateRoute message the registry actually
// dispatches so a test can inspect what the inner ConfigService would see.
// The stored Route is returned from GetRoute when getErr is nil; if getErr
// is non-nil, the Get fails so a test can exercise the merge-error path.
type routeCRUDCapture struct {
	configconnect.UnimplementedConfigServiceHandler
	stored         atomic.Pointer[configpb.Route]
	getErr         atomic.Value // error
	receivedUpdate atomic.Pointer[configpb.Route]
}

func (s *routeCRUDCapture) GetRoute(_ context.Context, req *connect.Request[configpb.GetRouteRequest]) (*connect.Response[configpb.GetRouteResponse], error) {
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

func (s *routeCRUDCapture) UpdateRoute(_ context.Context, req *connect.Request[configpb.UpdateRouteRequest]) (*connect.Response[configpb.UpdateRouteResponse], error) {
	clone := proto.Clone(req.Msg.Route).(*configpb.Route)
	s.receivedUpdate.Store(clone)
	return connect.NewResponse(&configpb.UpdateRouteResponse{Route: clone}), nil
}

// TestUpdate_FailsClosedOnInnerGetError locks the contract that a transient
// inner Get* failure surfaces an MCP tool error and refuses the Update,
// rather than dispatching the schema-stripped sparse input that would wipe
// every sensitive field on the persisted record.
func TestUpdate_FailsClosedOnInnerGetError(t *testing.T) {
	t.Parallel()

	id := "r-1"
	impl := &routeCRUDCapture{}
	impl.stored.Store(&configpb.Route{
		Id:           &id,
		From:         "https://existing.example",
		TlsClientKey: "EXISTING-PRIVATE-KEY",
	})
	impl.getErr.Store(error(connect.NewError(connect.CodeUnavailable, errors.New("upstream offline"))))

	session := connectMCP(t, newTestServer(t, impl))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resp, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "update_route",
		Arguments: map[string]any{
			"route": map[string]any{"id": id, "description": "renamed"},
		},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError,
		"merge failure must surface as MCP tool error; %+v", resp.Content)
	assert.Nil(t, impl.receivedUpdate.Load(),
		"Update must NOT be dispatched when applyUpdatePatch errors")
}

// TestUpdate_RefusesWithMissingEntityID locks the contract that an Update
// with no entity id is rejected at the MCP boundary. Without the id the
// merge cannot fetch the existing record, so dispatching the sparse input
// would wipe every sensitive field on the entity.
func TestUpdate_RefusesWithMissingEntityID(t *testing.T) {
	t.Parallel()

	id := "r-1"
	impl := &routeCRUDCapture{}
	impl.stored.Store(&configpb.Route{
		Id:           &id,
		From:         "https://existing.example",
		TlsClientKey: "EXISTING-PRIVATE-KEY",
	})

	session := connectMCP(t, newTestServer(t, impl))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resp, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "update_route",
		Arguments: map[string]any{
			"route": map[string]any{"description": "renamed-without-id"},
		},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError, "Update without id must surface an MCP tool error")
	assert.Nil(t, impl.receivedUpdate.Load(),
		"Update must NOT be dispatched when the entity id is missing")
}

// settingsCRUDCapture captures the UpdateSettings message that reaches the
// inner handler so a test can prove what the LLM actually wrote.
type settingsCRUDCapture struct {
	configconnect.UnimplementedConfigServiceHandler
	stored         atomic.Pointer[configpb.Settings]
	receivedUpdate atomic.Pointer[configpb.Settings]
}

func (s *settingsCRUDCapture) GetSettings(_ context.Context, _ *connect.Request[configpb.GetSettingsRequest]) (*connect.Response[configpb.GetSettingsResponse], error) {
	got := s.stored.Load()
	if got == nil {
		return connect.NewResponse(&configpb.GetSettingsResponse{Settings: &configpb.Settings{}}), nil
	}
	return connect.NewResponse(&configpb.GetSettingsResponse{Settings: got}), nil
}

func (s *settingsCRUDCapture) UpdateSettings(_ context.Context, req *connect.Request[configpb.UpdateSettingsRequest]) (*connect.Response[configpb.UpdateSettingsResponse], error) {
	clone := proto.Clone(req.Msg.Settings).(*configpb.Settings)
	s.receivedUpdate.Store(clone)
	return connect.NewResponse(&configpb.UpdateSettingsResponse{Settings: clone}), nil
}

// TestUpdate_RefusesListWithNestedSensitive locks the contract that an
// Update overlay touching a list/map of messages whose element type holds
// sensitive descendants is refused with a clear error. Wholesale list
// replacement would wipe nested secret values (e.g. Settings.certificates,
// where Settings.Certificate.key_bytes is sensitive but the LLM cannot
// supply it through the schema).
func TestUpdate_RefusesListWithNestedSensitive(t *testing.T) {
	t.Parallel()

	impl := &settingsCRUDCapture{}
	impl.stored.Store(&configpb.Settings{
		Certificates: []*configpb.Settings_Certificate{
			{Id: "cert-1", CertBytes: []byte("CERT-A"), KeyBytes: []byte("PRIVATE-KEY-A")},
			{Id: "cert-2", CertBytes: []byte("CERT-B"), KeyBytes: []byte("PRIVATE-KEY-B")},
		},
	})

	session := connectMCP(t, newTestServer(t, impl))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resp, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "update_settings",
		Arguments: map[string]any{
			"settings": map[string]any{
				"certificates": []any{
					map[string]any{"id": "cert-1", "certBytes": "Q0VSVC1B"}, // base64("CERT-A")
				},
			},
		},
	})
	require.NoError(t, err)
	require.True(t, resp.IsError,
		"sparse update on a list-of-message with nested sensitive descendants must surface an MCP tool error; %+v", resp.Content)
	assert.Nil(t, impl.receivedUpdate.Load(),
		"UpdateSettings must NOT be dispatched when the merge would wholesale-replace certificates")

	var bodyText string
	for _, part := range resp.Content {
		if tc, ok := part.(*mcp.TextContent); ok {
			bodyText += tc.Text
		}
	}
	assert.Contains(t, bodyText, "certificates",
		"the rejection should name the offending field; got %q", bodyText)
}

// TestUpdate_PreservesSensitiveForIDWithControlByte covers the case where
// an entity id contains a non-printable byte (here 0x1F). Encoding the
// inner Get* request via json.Marshal — rather than fmt's %q verb, which
// produces non-JSON Go-syntax escapes — keeps the round-trip clean so the
// merge succeeds and preserves every existing sensitive field.
func TestUpdate_PreservesSensitiveForIDWithControlByte(t *testing.T) {
	t.Parallel()

	id := "r-with-\x1f-controlchar"
	impl := &routeCRUDCapture{}
	impl.stored.Store(&configpb.Route{
		Id:           &id,
		From:         "https://existing.example",
		TlsClientKey: "EXISTING-PRIVATE-KEY",
	})

	session := connectMCP(t, newTestServer(t, impl))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	resp, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "update_route",
		Arguments: map[string]any{
			"route": map[string]any{"id": id, "description": "renamed"},
		},
	})
	require.NoError(t, err)
	require.False(t, resp.IsError, "%+v", resp.Content)

	dispatched := impl.receivedUpdate.Load()
	require.NotNil(t, dispatched, "Update must be dispatched after merge succeeded")
	assert.Equal(t, "EXISTING-PRIVATE-KEY", dispatched.GetTlsClientKey(),
		"merge must preserve tls_client_key for ids containing non-printable bytes")
}
