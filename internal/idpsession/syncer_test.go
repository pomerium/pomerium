package idpsession

import (
	"context"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	dtestutil "github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
)

type testSyncerReconciler struct {
	t          *testing.T
	client     databroker.DataBrokerServiceClient
	clock      *testClock
	syncer     *identitySyncer
	reconciler *synchronizedReconciler
}

func newSyncerReconcilerForTest(t *testing.T, now time.Time, authenticator identity.Authenticator) *testSyncerReconciler {
	t.Helper()
	if authenticator == nil {
		authenticator = newMockAuthenticator(t)
	}
	client := dtestutil.NewTestDatabroker(t)
	clientB := databroker.NewStaticClientGetter(client)
	clock := newTestClock(now)

	refreshConfig := *DefaultRefreshConfig
	refreshConfig.Now = clock.Now
	refreshConfig.SessionRefreshGracePeriod = 0
	refreshConfig.SessionRefreshCoolOffDuration = 0
	refreshConfig.RefreshSessionAtIDTokenExpiration = false
	refreshConfig.UpdateUserInfoInterval = 24 * time.Hour

	q := NewChangeQueue()
	idle := NewIdleTracker()
	idx := NewIdentityIndex(q, idle)
	reconciler := newSynchronizedReconciler(clientB, idx, q, idle, time.Hour, clock.Now)
	refreshMgr := newRefreshManager(refreshConfig, idx, clientB, func(context.Context, string) (identity.Authenticator, error) {
		return authenticator, nil
	})
	t.Cleanup(refreshMgr.Close)

	return &testSyncerReconciler{
		t:          t,
		client:     client,
		clock:      clock,
		syncer:     newIdentitySyncer(clientB, idx, refreshMgr, reconciler, clock.Now),
		reconciler: reconciler,
	}
}

func (h *testSyncerReconciler) put(records ...*databroker.Record) {
	h.t.Helper()
	_, err := h.client.Put(h.t.Context(), &databroker.PutRequest{Records: records})
	require.NoError(h.t, err)
	h.syncer.UpdateRecords(h.t.Context(), 0, records)
}

func (h *testSyncerReconciler) reconcile() {
	h.reconciler.reconcile(h.t.Context())
}

const eventuallyTimeout = 5 * time.Second

func TestIDPSessionReconciler(t *testing.T) {
	zerolog.SetGlobalLevel(zerolog.Disabled)

	t.Run("propagation", func(t *testing.T) {
		now := time.Now()
		h := newSyncerReconcilerForTest(t, now, nil)

		idpSession := newIDPSession("id1", nil, "foo", now.Add(time.Hour))
		records := []*databroker.Record{databroker.NewRecord(idpSession)}
		records = append(records, boundRecords(now, idpSession.GetId())...)
		h.put(records...)
		h.reconcile()
		assertDependentTokensEqual(t, h.client, "foo")

		idpSession.OauthToken.AccessToken = "bar"
		idpSession.OauthToken.RefreshToken = "bar"
		h.put(databroker.NewRecord(idpSession))
		h.reconcile()
		assertDependentTokensEqual(t, h.client, "bar")
	})

	t.Run("deletion", func(t *testing.T) {
		now := time.Now()
		h := newSyncerReconcilerForTest(t, now, nil)

		idpSession := newIDPSession("id1", nil, "foo", now.Add(time.Hour))
		records := []*databroker.Record{databroker.NewRecord(idpSession)}
		records = append(records, boundRecords(now, idpSession.GetId())...)
		h.put(records...)
		h.reconcile()
		assertRecordExists(t, h.client, sessionTypeURL, "s1")
		assertRecordExists(t, h.client, sessionTypeURL, "m1")

		h.put(deletedRecord(idpSession, now))
		h.reconcile()
		for _, id := range []string{"s1", "m1"} {
			assertRecordDeleted(t, h.client, bindingTypeURL, id)
		}
		assertRecordDeleted(t, h.client, sessionTypeURL, "s1")
		assertRecordDeleted(t, h.client, sessionTypeURL, "m1")
	})

	t.Run("idle cleanup", func(t *testing.T) {
		now := time.Now()
		h := newSyncerReconcilerForTest(t, now, nil)

		idpSession := newIDPSession("idle-session", nil, "token", now.Add(2*time.Hour))
		h.put(databroker.NewRecord(idpSession))
		h.reconcile()
		assertRecordExists(t, h.client, idpSessionTypeURL, idpSession.GetId())

		h.clock.Advance(time.Hour + time.Second)
		h.reconcile()
		assertRecordDeleted(t, h.client, idpSessionTypeURL, idpSession.GetId())
	})
}

func TestBindingReconciler(t *testing.T) {
	zerolog.SetGlobalLevel(zerolog.Disabled)

	t.Run("propagate updates", func(t *testing.T) {
		type tc struct {
			name      string
			dependent idpsession.BindableRecord
			protocol  idpsession.BindingProtocol
			assert    func(assert.TestingT, databroker.DataBrokerServiceClient, string)
		}

		now := time.Now()
		for _, c := range []tc{
			{
				name: "browser session",
				dependent: &session.Session{
					Id:        "s1",
					UserId:    "u1",
					ExpiresAt: timestamppb.New(now.Add(time.Hour)),
				},
				protocol: idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER,
				assert: func(t assert.TestingT, client databroker.DataBrokerServiceClient, token string) {
					got, ok := assertGetRecord(t, client, &session.Session{Id: "s1"})
					if !ok {
						return
					}
					assert.Equal(t, token, got.GetOauthToken().GetAccessToken())
				},
			},
			{
				name: "MCP session",
				dependent: &session.Session{
					Id:        "m1",
					UserId:    "u1",
					ExpiresAt: timestamppb.New(now.Add(time.Hour)),
				},
				protocol: idpsession.BindingProtocol_BINDING_PROTOCOL_MCP,
				assert: func(t assert.TestingT, client databroker.DataBrokerServiceClient, token string) {
					got, ok := assertGetRecord(t, client, &session.Session{Id: "m1"})
					if !ok {
						return
					}
					assert.Equal(t, token, got.GetOauthToken().GetAccessToken())
				},
			},
		} {
			t.Run(c.name, func(t *testing.T) {
				h := newSyncerReconcilerForTest(t, now, nil)
				idpSession := newIDPSession("id1", nil, "foo", now.Add(time.Hour))
				records := idpsession.NewBoundRecords(
					idpSession.GetId(), "u1", c.protocol, nil, c.dependent,
				)
				h.put(append([]*databroker.Record{databroker.NewRecord(idpSession)}, records...)...)
				h.reconcile()
				c.assert(t, h.client, "foo")
			})
		}
	})

	t.Run("deletion", func(t *testing.T) {
		type tc struct {
			name   string
			delete func(*testSyncerReconciler, time.Time)
		}

		for _, c := range []tc{
			{
				name: "binding",
				delete: func(h *testSyncerReconciler, now time.Time) {
					binding := idpsession.NewBinding(
						"id1", "u1", idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER,
						&session.Session{Id: "s1"}, nil,
					)
					h.put(deletedRecord(binding, now))
				},
			},
			{
				name: "dependent",
				delete: func(h *testSyncerReconciler, now time.Time) {
					h.put(deletedRecord(&session.Session{Id: "s1"}, now))
				},
			},
		} {
			t.Run(c.name, func(t *testing.T) {
				now := time.Now()
				h := newSyncerReconcilerForTest(t, now, nil)
				idpSession := newIDPSession("id1", nil, "foo", now.Add(time.Hour))
				dependent := &session.Session{
					Id:        "s1",
					UserId:    "u1",
					ExpiresAt: timestamppb.New(now.Add(time.Hour)),
				}
				records := idpsession.NewBoundRecords(
					idpSession.GetId(), "u1", idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER,
					nil, dependent,
				)
				h.put(append([]*databroker.Record{databroker.NewRecord(idpSession)}, records...)...)
				h.reconcile()
				assertRecordExists(t, h.client, bindingTypeURL, dependent.GetId())
				assertRecordExists(t, h.client, sessionTypeURL, dependent.GetId())

				c.delete(h, now)
				h.reconcile()
				assertRecordDeleted(t, h.client, bindingTypeURL, dependent.GetId())
				assertRecordDeleted(t, h.client, sessionTypeURL, dependent.GetId())
			})
		}
	})
}

func newIDPSession(id string, sid *string, token string, expiresAt time.Time) *idpsession.IDPSession {
	return &idpsession.IDPSession{
		Id:     id,
		Sid:    sid,
		IdpId:  "p1",
		UserId: "u1",
		OauthToken: &idpsession.OAuthToken{
			AccessToken:  token,
			RefreshToken: token,
			TokenType:    "Bearer",
			ExpiresAt:    timestamppb.New(expiresAt),
		},
	}
}
