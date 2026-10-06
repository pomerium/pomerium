package authenticateflow

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/httputil"
	dtestutil "github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestBindingManager(t *testing.T) {
	t.Run("get IDP sessions", func(t *testing.T) {
		client := dtestutil.NewTestDatabroker(t)
		now := time.Now()
		resource := "r1"
		address := "a1"
		sid := "sid1"
		put(t, client,
			databroker.NewRecord(&idpsession.IDPSession{Id: "idp1", UserId: "u1", Sid: &sid, InitiatedAt: timestamppb.New(now), InitatedBy: &resource, InitiatedByAddr: &address}),
			databroker.NewRecord(&idpsession.IDPSession{Id: "idp2", UserId: "u1", InitiatedAt: timestamppb.New(now)}),
			databroker.NewRecord(&idpsession.IDPSession{Id: "idp3", UserId: "u2", InitiatedAt: timestamppb.New(now)}),
			databroker.NewRecord(idpsession.NewBinding("idp1", "u1", idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER, &session.Session{Id: "s1"}, nil)),
		)

		got, currentIDPSessionID, err := NewBindingManager(client).GetIDPSessions(t.Context(), &session.Handle{Id: "s1", UserId: "u1"})
		require.NoError(t, err)
		assert.Equal(t, "idp1", currentIDPSessionID)
		assert.Equal(t, []handlers.IDPSessionData{
			{
				IDPSessionID:  "idp1",
				SID:           "sid1",
				Resource:      "r1",
				ClientAddress: "a1",
				InitiatedAt:   now.UTC().Format(time.RFC1123),
			},
			{
				IDPSessionID:  "idp2",
				Resource:      "Uknown client",
				ClientAddress: "unknown client address",
				InitiatedAt:   now.UTC().Format(time.RFC1123),
			},
		}, got)
	})

	t.Run("get bindings", func(t *testing.T) {
		client := dtestutil.NewTestDatabroker(t)
		now := time.Now()
		put(t, client,
			sshSessionBinding("sshkey-SHA256:b", &session.SessionBinding{
				Protocol: session.ProtocolSSH, SessionId: "s1", UserId: "u1",
				IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(time.Hour)),
				Details: map[string]string{session.DetailSourceAddr: "a1"},
			}),
			sshSessionBinding("sshkey-SHA256:a", &session.SessionBinding{
				Protocol: session.ProtocolSSH, SessionId: "s1", UserId: "u1",
				IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(time.Hour)),
			}),
			sshSessionBinding("sshkey-SHA256:a", &session.IdentityBinding{UserId: "u1"}),
			sshSessionBinding("sshkey-SHA256:c", &session.SessionBinding{
				Protocol: session.ProtocolSSH, SessionId: "s2", UserId: "u2",
				IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(time.Hour)),
			}),
			databroker.NewRecord(idpsession.NewBinding("ss1", "u1", idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER, &session.Session{Id: "s1"}, nil)),
			databroker.NewRecord(idpsession.NewBinding("ss2", "u2", idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER, &session.Session{Id: "s2"}, nil)),
			databroker.NewRecord(&session.Session{Id: "m1"}),
			databroker.NewRecord(&session.Session{Id: "s2"}),
			databroker.NewRecord(&idpsession.Binding{
				Id:           "m1",
				TypeUrl:      protoutil.GetTypeURL(new(session.Session)),
				IdpSessionId: "ss1",
				UserId:       "u1",
				Protocol:     idpsession.BindingProtocol_BINDING_PROTOCOL_MCP,
				InitiatedAt:  timestamppb.New(now),
				Details:      map[string]string{"client-ip": "a2", "mcp_client_id": "c1"},
			}),
		)

		got, err := NewBindingManager(client).GetBindings(t.Context(), &session.Handle{Id: "s1", UserId: "u1"})
		require.NoError(t, err)
		assert.Equal(t, []handlers.SessionBindingData{
			{
				IDPSessionID:     "ss1",
				SessionBindingID: "m1",
				Protocol:         "MCP",
				Resource:         "c1",
				ClientAddress:    "a2",
				InitiatedAt:      now.UTC().Format(time.RFC1123),
				ExpiresAt:        "Until revoked or IDP expires",
			},
			{
				IDPSessionID:       "ss1",
				SessionBindingID:   "sshkey-SHA256:a",
				Protocol:           session.ProtocolSSH,
				Resource:           "SSH key",
				ClientAddress:      "Not recorded",
				InitiatedAt:        now.UTC().Format(time.RFC1123),
				ExpiresAt:          "Until revoked",
				HasIdentityBinding: true,
				DetailsSSH: &handlers.ProtocolDetailsSSH{
					FingerprintID: "a",
					SourceAddress: "Not recorded",
				},
			},
			{
				IDPSessionID:     "ss1",
				SessionBindingID: "sshkey-SHA256:b",
				Protocol:         session.ProtocolSSH,
				Resource:         "SSH key",
				ClientAddress:    "a1",
				InitiatedAt:      now.UTC().Format(time.RFC1123),
				ExpiresAt:        now.Add(time.Hour).UTC().Format(time.RFC1123),
				DetailsSSH: &handlers.ProtocolDetailsSSH{
					FingerprintID: "b",
					SourceAddress: "a1",
				},
			},
		}, got)

		got2, err := NewBindingManager(client).GetBindings(t.Context(), &session.Handle{Id: "s2", UserId: "u2"})
		require.NoError(t, err)
		assert.Equal(t, []handlers.SessionBindingData{
			{
				IDPSessionID:       "ss2",
				SessionBindingID:   "sshkey-SHA256:c",
				Protocol:           session.ProtocolSSH,
				Resource:           "SSH key",
				ClientAddress:      "Not recorded",
				InitiatedAt:        now.UTC().Format(time.RFC1123),
				ExpiresAt:          now.Add(time.Hour).UTC().Format(time.RFC1123),
				HasIdentityBinding: false,
				DetailsSSH: &handlers.ProtocolDetailsSSH{
					FingerprintID: "c",
					SourceAddress: "Not recorded",
				},
			},
		}, got2)
	})
	t.Run("revoke binding", func(t *testing.T) {
		t.Run("SSH", func(t *testing.T) {
			client := dtestutil.NewTestDatabroker(t)
			put(t, client, sshSessionBinding("b1", &session.SessionBinding{UserId: "u1"}))

			err := NewBindingManager(client).RevokeBinding(t.Context(), BindingID{
				Protocol:  session.ProtocolSSH,
				UserID:    "u1",
				BindingID: "b1",
			})
			require.NoError(t, err)
			assertBindingRecordDeleted(t, client, new(session.SessionBinding), "b1")
		})

		for _, tc := range []struct {
			name       string
			protocol   idpsession.BindingProtocol
			request    BindingID
			wantStatus int
		}{
			{
				name:       "MCP",
				protocol:   idpsession.BindingProtocol_BINDING_PROTOCOL_MCP,
				request:    BindingID{Protocol: "MCP", UserID: "u1", BindingID: "b1"},
				wantStatus: http.StatusOK,
			},
			{
				name:       "wrong user",
				protocol:   idpsession.BindingProtocol_BINDING_PROTOCOL_MCP,
				request:    BindingID{Protocol: "MCP", UserID: "u2", BindingID: "b1"},
				wantStatus: http.StatusNotFound,
			},
			{
				name:       "browser binding",
				protocol:   idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER,
				request:    BindingID{Protocol: "MCP", UserID: "u1", BindingID: "b1"},
				wantStatus: http.StatusBadRequest,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				client := dtestutil.NewTestDatabroker(t)
				binding := idpsession.NewBinding("idp1", "u1", tc.protocol, &session.Session{Id: "b1"}, nil)
				put(t, client, databroker.NewRecord(binding))

				err := NewBindingManager(client).RevokeBinding(t.Context(), tc.request)
				if tc.wantStatus == http.StatusOK {
					require.NoError(t, err)
					assertBindingRecordDeleted(t, client, new(session.SessionBinding), "b1")
				} else {
					assertHTTPStatusFromErr(t, err, tc.wantStatus)
				}
			})
		}

		for _, tc := range []struct {
			name       string
			request    BindingID
			wantStatus int
		}{
			{
				name:       "missing binding",
				request:    BindingID{Protocol: "MCP", UserID: "u1", BindingID: "b1"},
				wantStatus: http.StatusNotFound,
			},
			{
				name:       "browser request",
				request:    BindingID{Protocol: "Browser"},
				wantStatus: http.StatusBadRequest,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				client := dtestutil.NewTestDatabroker(t)

				err := NewBindingManager(client).RevokeBinding(t.Context(), tc.request)
				assertHTTPStatusFromErr(t, err, tc.wantStatus)
			})
		}
	})

	t.Run("revoke IDP session", func(t *testing.T) {
		for _, tc := range []struct {
			name           string
			sid            *string
			wantDeletedIDs []string
			wantKeptIDs    []string
		}{
			{
				name:           "shared SID",
				sid:            new("sid1"),
				wantDeletedIDs: []string{"idp1", "idp2", "idp4"},
				wantKeptIDs:    []string{"idp3"},
			},
			{
				name:           "no SID",
				wantDeletedIDs: []string{"idp1", "idp2", "idp3", "idp4"},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				client := dtestutil.NewTestDatabroker(t)
				put(t, client,
					databroker.NewRecord(&idpsession.IDPSession{Id: "idp1", UserId: "u1", Sid: tc.sid}),
					databroker.NewRecord(&idpsession.IDPSession{Id: "idp2", UserId: "u1", Sid: tc.sid}),
					databroker.NewRecord(&idpsession.IDPSession{Id: "idp3", UserId: "u1", Sid: new("sid2")}),
					databroker.NewRecord(&idpsession.IDPSession{Id: "idp4", UserId: "u1", Sid: tc.sid}),
					databroker.NewRecord(idpsession.NewBinding("idp1", "u1", idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER, &session.Session{Id: "s1"}, nil)),
				)

				got, err := NewBindingManager(client).DeleteUpstreamIDPSessions(t.Context(), &session.Handle{Id: "s1", UserId: "u1"})
				require.NoError(t, err)
				assert.Equal(t, "idp1", got.Source.GetId())
				assert.ElementsMatch(t, tc.wantDeletedIDs, idpSessionIDs(got.Sessions))
				for _, id := range tc.wantDeletedIDs {
					assertBindingRecordDeleted(t, client, new(idpsession.IDPSession), id)
				}
				for _, id := range tc.wantKeptIDs {
					assertBindingRecordExists(t, client, new(idpsession.IDPSession), id)
				}
			})
		}

		t.Run("edgecases", func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				handle *session.Handle
			}{
				{name: "nil handle"},
				{name: "missing binding", handle: &session.Handle{Id: "s1", UserId: "u1"}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					client := dtestutil.NewTestDatabroker(t)

					_, err := NewBindingManager(client).DeleteUpstreamIDPSessions(t.Context(), tc.handle)
					assertHTTPStatusFromErr(t, err, http.StatusNotFound)
				})
			}
		})
	})
}

func put(t *testing.T, client databroker.DataBrokerServiceClient, records ...*databroker.Record) {
	t.Helper()
	_, err := client.Put(t.Context(), &databroker.PutRequest{Records: records})
	require.NoError(t, err)
}

func sshSessionBinding(id string, message proto.Message) *databroker.Record {
	return &databroker.Record{Id: id, Type: protoutil.GetTypeURL(message), Data: protoutil.NewAny(message)}
}

func assertBindingRecordDeleted(t *testing.T, client databroker.DataBrokerServiceClient, message proto.Message, id string) {
	t.Helper()
	_, err := client.Get(t.Context(), &databroker.GetRequest{Type: protoutil.GetTypeURL(message), Id: id})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func assertBindingRecordExists(t *testing.T, client databroker.DataBrokerServiceClient, message proto.Message, id string) {
	t.Helper()
	_, err := client.Get(t.Context(), &databroker.GetRequest{Type: protoutil.GetTypeURL(message), Id: id})
	assert.NoError(t, err)
}

func assertHTTPStatusFromErr(t *testing.T, err error, want int) {
	t.Helper()
	var httpErr *httputil.HTTPError
	if assert.ErrorAs(t, err, &httpErr) {
		assert.Equal(t, want, httpErr.Status)
	}
}

func idpSessionIDs(sessions []*idpsession.IDPSession) []string {
	ids := make([]string, len(sessions))
	for i, session := range sessions {
		ids[i] = session.GetId()
	}
	return ids
}
