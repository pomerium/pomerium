package idpsession

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	oauth21 "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestDataStoreChangeSet(t *testing.T) {
	t.Run("propagate all", func(t *testing.T) {
		ds := newDataStore(time.Now)

		idpSessionID := "foo"

		now := timestamppb.Now()

		ds.putIDPSession(&idpsession.IDPSession{
			Id:         idpSessionID,
			RawIdToken: "asd",
			IdToken: &idpsession.IDToken{
				Issuer:    "iss",
				Subject:   "ass",
				ExpiresAt: now,
				IssuedAt:  now,
				Raw:       "asd",
			},
			OauthToken: &idpsession.OAuthToken{
				AccessToken:  idpSessionID,
				TokenType:    "Bearer",
				ExpiresAt:    now,
				RefreshToken: "refresh",
			},
			Claims: &structpb.Struct{},
			IdpId:  "idp",
		})

		ds.updateMapping(&idpsession.Binding{
			Id:           "browser1",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/session.Session",
		})

		ds.updateMapping(&idpsession.Binding{
			Id:           "browser2",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/session.Session",
		})

		ds.updateMapping(&idpsession.Binding{
			Id:           "userID",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/user.User",
		})

		ds.updateMapping(&idpsession.Binding{
			Id:           "mcp-client-1",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/oauth21.MCPRefreshToken",
		})

		ds.updateMapping(&idpsession.Binding{
			Id:           "mcp-client-2",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/oauth21.MCPRefreshToken",
		})

		ds.addRecord(databroker.NewRecord(&session.Session{
			Id: "browser1",
		}))

		ds.addRecord(databroker.NewRecord(&session.Session{
			Id: "browser2",
		}))
		ds.addRecord(databroker.NewRecord(&user.User{
			Id: "userID",
		}))

		ds.addRecord(databroker.NewRecord(&oauth21.MCPRefreshToken{
			Id: "mcp-client-1",
		}))

		ds.addRecord(databroker.NewRecord(&oauth21.MCPRefreshToken{
			Id: "mcp-client-2",
		}))

		currentSet, err := ds.getCurrentChangesetLocked(t.Context())
		require.NoError(t, err)

		targetSet, err := ds.targetChangeSetLocked(t.Context())
		require.NoError(t, err)
		_ = targetSet

		assertRecordSetBundleNotEqual(t, currentSet, targetSet)
	})

	t.Run("on idpsession delete", func(t *testing.T) {
		ds := newDataStore(time.Now)

		idpSessionID := "foo"

		ds.putIDPSession(&idpsession.IDPSession{
			Id:    idpSessionID,
			IdpId: "idp",
		})
		ds.updateMapping(&idpsession.Binding{
			Id:           "browser1",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/session.Session",
		})
		ds.updateMapping(&idpsession.Binding{
			Id:           "userID",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/user.User",
		})
		ds.addRecord(databroker.NewRecord(&session.Session{Id: "browser1"}))
		ds.addRecord(databroker.NewRecord(&user.User{Id: "userID"}))

		ds.deleteIDPSession(idpSessionID)

		targetSet, err := ds.targetChangeSetLocked(t.Context())
		require.NoError(t, err)

		_, ok := targetSet.Get("type.googleapis.com/idpsession.IDPSession", idpSessionID)
		assert.False(t, ok, "the idpsession record should be dropped")

		// TODO: an absent idpsession.IDPSession doesn't cause revocation of bindings.
		want := make(databroker.RecordSetBundle)
		want.Add(databroker.NewRecord(&idpsession.Binding{
			Id:           "browser1",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/session.Session",
		}))
		want.Add(databroker.NewRecord(&idpsession.Binding{
			Id:           "userID",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/user.User",
		}))
		assertRecordSetEqual(t,
			want["type.googleapis.com/idpsession.Binding"],
			targetSet["type.googleapis.com/idpsession.Binding"],
		)
	})

	t.Run("on idpsession revoke", func(t *testing.T) {
		now := time.Now()
		ds := newDataStore(func() time.Time { return now })

		idpSessionID := "foo"
		invalidatedAt := timestamppb.New(now)

		ds.putIDPSession(&idpsession.IDPSession{
			Id: idpSessionID,
			State: &idpsession.SessionState{
				State:         idpsession.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID,
				InvalidatedAt: invalidatedAt,
				Details:       "user revoked",
			},
		})
		ds.updateMapping(&idpsession.Binding{
			Id:           "browser1",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/session.Session",
		})
		ds.updateMapping(&idpsession.Binding{
			Id:           "userID",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/user.User",
		})
		ds.addRecord(databroker.NewRecord(&session.Session{Id: "browser1"}))
		ds.addRecord(databroker.NewRecord(&user.User{Id: "userID"}))

		targetSet, err := ds.targetChangeSetLocked(t.Context())
		require.NoError(t, err)

		// associated bindings are marked revoked. user.User's are never deleted.
		for _, id := range []string{"browser1", "userID"} {
			rec, ok := targetSet.Get("type.googleapis.com/idpsession.Binding", id)
			if !assert.True(t, ok, id) {
				continue
			}
			binding := &idpsession.Binding{}
			require.NoError(t, rec.GetData().UnmarshalTo(binding))
			assert.Equal(t, idpsession.BindingState_BindingState_REVOKED, binding.GetState(), id)
			assert.NotNil(t, binding.GetRevokedAt(), id)
		}

		_, ok := targetSet.Get("type.googleapis.com/idpsession.IDPSession", idpSessionID)
		assert.True(t, ok, "the idpsession record should be retained within its grace period")
		_, ok = targetSet.Get("type.googleapis.com/session.Session", "browser1")
		assert.False(t, ok, "a revoked binding should not propagate its dependent record")
		_, ok = targetSet.Get("type.googleapis.com/user.User", "userID")
		assert.True(t, ok, "user records should never be deleted")

		// The revocation must be a difference the reconciler can act on.
		currentSet, err := ds.getCurrentChangesetLocked(t.Context())
		require.NoError(t, err)
		assertRecordSetNotEqual(t,
			currentSet["type.googleapis.com/idpsession.Binding"],
			targetSet["type.googleapis.com/idpsession.Binding"],
		)

		// after the grace period the bindings should be cleaned up.
		now = now.Add(ds.bindingGracePeriod + time.Minute)
		targetSet, err = ds.targetChangeSetLocked(t.Context())
		require.NoError(t, err)
		assert.Empty(t, targetSet["type.googleapis.com/idpsession.Binding"])
	})

	t.Run("binding revoked grace period", func(t *testing.T) {
		now := time.Now()
		ds := newDataStore(func() time.Time { return now })

		idpSessionID := "foo"
		ds.putIDPSession(&idpsession.IDPSession{Id: idpSessionID})
		ds.updateMapping(&idpsession.Binding{
			Id:           "browser1",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/session.Session",
			State:        idpsession.BindingState_BindingState_REVOKED,
			RevokedAt:    timestamppb.New(now.Add(-ds.bindingGracePeriod + time.Minute)),
		})
		ds.addRecord(databroker.NewRecord(&session.Session{Id: "browser1"}))

		// bindings still exist, but are revoked.
		targetSet, err := ds.targetChangeSetLocked(t.Context())
		require.NoError(t, err)
		_, ok := targetSet.Get("type.googleapis.com/idpsession.Binding", "browser1")
		assert.True(t, ok, "revoked binding should be retained within the grace period")
		_, ok = targetSet.Get("type.googleapis.com/session.Session", "browser1")
		assert.False(t, ok, "revoked binding should not propagate its dependent record")

		// after the grace period the bindings should be cleaned up.
		now = now.Add(2 * time.Minute)
		targetSet, err = ds.targetChangeSetLocked(t.Context())
		require.NoError(t, err)
		_, ok = targetSet.Get("type.googleapis.com/idpsession.Binding", "browser1")
		assert.False(t, ok, "revoked binding should be dropped after the grace period")
	})

	t.Run("idpsession invalidated grace period", func(t *testing.T) {
		now := time.Now()
		ds := newDataStore(func() time.Time { return now })

		idpSessionID := "foo"
		ds.putIDPSession(&idpsession.IDPSession{
			Id: idpSessionID,
			State: &idpsession.SessionState{
				State:         idpsession.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID,
				InvalidatedAt: timestamppb.New(now.Add(-ds.idpSessionGracePeriod + time.Minute)),
			},
		})

		targetSet, err := ds.targetChangeSetLocked(t.Context())
		require.NoError(t, err)
		_, ok := targetSet.Get("type.googleapis.com/idpsession.IDPSession", idpSessionID)
		assert.True(t, ok, "invalidated idpsession should be retained within the grace period")

		now = now.Add(2 * time.Minute)
		targetSet, err = ds.targetChangeSetLocked(t.Context())
		require.NoError(t, err)
		_, ok = targetSet.Get("type.googleapis.com/idpsession.IDPSession", idpSessionID)
		assert.False(t, ok, "invalidated idpsession should be dropped after the grace period")
	})

	t.Run("invalid idpsession without invalidated at", func(t *testing.T) {
		now := time.Now()
		ds := newDataStore(func() time.Time { return now })

		idpSessionID := "foo"
		ds.putIDPSession(&idpsession.IDPSession{
			Id: idpSessionID,
			State: &idpsession.SessionState{
				State: idpsession.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID,
			},
		})
		ds.updateMapping(&idpsession.Binding{
			Id:           "browser1",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/session.Session",
		})
		ds.addRecord(databroker.NewRecord(&session.Session{Id: "browser1"}))

		targetSet, err := ds.targetChangeSetLocked(t.Context())
		require.NoError(t, err)

		// Revocation does not depend on invalidated_at, so the binding still
		// gets a revoked_at and ages out of the grace period.
		rec, ok := targetSet.Get("type.googleapis.com/idpsession.Binding", "browser1")
		require.True(t, ok)
		binding := &idpsession.Binding{}
		require.NoError(t, rec.GetData().UnmarshalTo(binding))
		assert.Equal(t, idpsession.BindingState_BindingState_REVOKED, binding.GetState())
		assert.NotNil(t, binding.GetRevokedAt())

		_, ok = targetSet.Get("type.googleapis.com/session.Session", "browser1")
		assert.False(t, ok, "a revoked binding should not propagate its dependent record")

		now = now.Add(ds.bindingGracePeriod + time.Minute)
		targetSet, err = ds.targetChangeSetLocked(t.Context())
		require.NoError(t, err)
		assert.Empty(t, targetSet["type.googleapis.com/idpsession.Binding"])
	})

	t.Run("dependent records applied", func(t *testing.T) {
		ds := newDataStore(time.Now)

		idpSessionID := "foo"
		now := timestamppb.Now()

		ds.putIDPSession(&idpsession.IDPSession{
			Id: idpSessionID,
			IdToken: &idpsession.IDToken{
				Issuer:    "iss",
				Subject:   "sub",
				ExpiresAt: now,
				IssuedAt:  now,
				Raw:       "raw-id-token",
			},
			OauthToken: &idpsession.OAuthToken{
				AccessToken:  "access",
				TokenType:    "Bearer",
				ExpiresAt:    now,
				RefreshToken: "refresh",
			},
		})
		ds.updateMapping(&idpsession.Binding{
			Id:           "browser1",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/session.Session",
		})
		ds.updateMapping(&idpsession.Binding{
			Id:           "mcp-client-1",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/oauth21.MCPRefreshToken",
		})
		ds.addRecord(databroker.NewRecord(&session.Session{Id: "browser1"}))
		ds.addRecord(databroker.NewRecord(&oauth21.MCPRefreshToken{Id: "mcp-client-1"}))

		targetSet, err := ds.targetChangeSetLocked(t.Context())
		require.NoError(t, err)

		wantSessions := make(databroker.RecordSetBundle)
		wantSessions.Add(databroker.NewRecord(&session.Session{
			Id: "browser1",
			IdToken: &session.IDToken{
				Issuer:    "iss",
				Subject:   "sub",
				ExpiresAt: now,
				IssuedAt:  now,
				Raw:       "raw-id-token",
			},
			OauthToken: &session.OAuthToken{
				AccessToken:  "access",
				TokenType:    "Bearer",
				ExpiresAt:    now,
				RefreshToken: "refresh",
			},
		}))
		assertRecordSetEqual(t,
			wantSessions["type.googleapis.com/session.Session"],
			targetSet["type.googleapis.com/session.Session"],
		)

		wantMCP := make(databroker.RecordSetBundle)
		wantMCP.Add(databroker.NewRecord(&oauth21.MCPRefreshToken{
			Id:                   "mcp-client-1",
			UpstreamRefreshToken: "refresh",
		}))
		assertRecordSetEqual(t,
			wantMCP["type.googleapis.com/oauth21.MCPRefreshToken"],
			targetSet["type.googleapis.com/oauth21.MCPRefreshToken"],
		)
	})

	t.Run("binding without dependent record", func(t *testing.T) {
		ds := newDataStore(time.Now)

		idpSessionID := "foo"
		ds.putIDPSession(&idpsession.IDPSession{Id: idpSessionID})
		ds.updateMapping(&idpsession.Binding{
			Id:           "browser1",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/session.Session",
		})

		currentSet, err := ds.getCurrentChangesetLocked(t.Context())
		require.NoError(t, err)
		_, ok := currentSet.Get("type.googleapis.com/session.Session", "browser1")
		assert.False(t, ok)

		targetSet, err := ds.targetChangeSetLocked(t.Context())
		require.NoError(t, err)
		_, ok = targetSet.Get("type.googleapis.com/idpsession.Binding", "browser1")
		assert.True(t, ok)
		_, ok = targetSet.Get("type.googleapis.com/session.Session", "browser1")
		assert.False(t, ok)
	})

	t.Run("binding without idpsession", func(t *testing.T) {
		ds := newDataStore(time.Now)

		// TODO : a missing IDPSession can be caused by a race of not seeing an IDPSession yet.
		ds.updateMapping(&idpsession.Binding{
			Id:           "browser1",
			IdpSessionId: "foo",
			TypeUrl:      "type.googleapis.com/session.Session",
		})
		ds.addRecord(databroker.NewRecord(&session.Session{Id: "browser1", UserId: "userID"}))

		targetSet, err := ds.targetChangeSetLocked(t.Context())
		require.NoError(t, err)

		want := make(databroker.RecordSetBundle)
		want.Add(databroker.NewRecord(&session.Session{Id: "browser1", UserId: "userID"}))
		assertRecordSetEqual(t,
			want["type.googleapis.com/session.Session"],
			targetSet["type.googleapis.com/session.Session"],
		)
	})

	t.Run("empty", func(t *testing.T) {
		ds := newDataStore(time.Now)

		currentSet, err := ds.getCurrentChangesetLocked(t.Context())
		require.NoError(t, err)

		targetSet, err := ds.targetChangeSetLocked(t.Context())
		require.NoError(t, err)

		assert.Empty(t, currentSet)
		assert.Empty(t, targetSet)
		assertRecordSetBundleEqual(t, currentSet, targetSet)
	})
}

func TestDataStore(t *testing.T) {
	t.Run("idpsession", func(t *testing.T) {
		ds := newDataStore(time.Now)
		ds.putIDPSession(&idpsession.IDPSession{
			Id: "foo",
		})
		ds.putIDPSession(&idpsession.IDPSession{
			Id: "bar",
		})

		_, ok1 := ds.idpSessions["foo"]
		assert.True(t, ok1)

		_, ok2 := ds.idpSessions["bar"]
		assert.True(t, ok2)

		ds.deleteIDPSession("foo")
		_, ok3 := ds.idpSessions["foo"]
		assert.False(t, ok3)
	})

	t.Run("get idpsession", func(t *testing.T) {
		ds := newDataStore(time.Now)

		assert.Nil(t, ds.getIDPSession("missing"))

		ds.putIDPSession(&idpsession.IDPSession{Id: "foo", IdpId: "idp"})

		got := ds.getIDPSession("foo")
		require.NotNil(t, got)
		assert.Equal(t, "idp", got.GetIdpId())

		got.IdpId = "mutated"
		// assert copy.
		assert.Equal(t, "idp", ds.getIDPSession("foo").GetIdpId())
	})

	t.Run("binding", func(t *testing.T) {
		ds := newDataStore(time.Now)

		b1 := &idpsession.Binding{
			Id:           "browser1",
			IdpSessionId: "foo",
			TypeUrl:      "type.googleapis.com/session.Session",
		}
		b2 := &idpsession.Binding{
			Id:           "browser2",
			IdpSessionId: "foo",
			TypeUrl:      "type.googleapis.com/session.Session",
		}
		b3 := &idpsession.Binding{
			Id:           "browser3",
			IdpSessionId: "bar",
			TypeUrl:      "type.googleapis.com/session.Session",
		}

		ds.updateMapping(b1)
		ds.updateMapping(b2)
		ds.updateMapping(b3)

		assert.Len(t, ds.idpToBindings["foo"], 2)
		assert.Len(t, ds.idpToBindings["bar"], 1)

		ds.updateMapping(&idpsession.Binding{
			Id:           "browser1",
			IdpSessionId: "foo",
			TypeUrl:      "type.googleapis.com/session.Session",
			State:        idpsession.BindingState_BindingState_REVOKED,
		})
		assert.Len(t, ds.idpToBindings["foo"], 2)
		assert.Equal(t,
			idpsession.BindingState_BindingState_REVOKED,
			ds.idpToBindings["foo"]["browser1"].GetState(),
		)

		ds.deleteMapping(b1)
		_, ok := ds.idpToBindings["foo"]["browser1"]
		assert.False(t, ok)
		assert.Len(t, ds.idpToBindings["foo"], 1)

		ds.deleteMapping(b1)
		ds.deleteMapping(&idpsession.Binding{Id: "browser1", IdpSessionId: "unknown"})
		assert.Len(t, ds.idpToBindings["foo"], 1)
		assert.NotContains(t, ds.idpToBindings, "unknown")
	})

	t.Run("delete idpsession keeps bindings as observed", func(t *testing.T) {
		ds := newDataStore(time.Now)

		ds.putIDPSession(&idpsession.IDPSession{Id: "foo"})
		ds.updateMapping(&idpsession.Binding{
			Id:           "browser1",
			IdpSessionId: "foo",
			TypeUrl:      "type.googleapis.com/session.Session",
		})

		ds.deleteIDPSession("foo")

		assert.Equal(t,
			idpsession.BindingState_BindingState_ACTIVE,
			ds.idpToBindings["foo"]["browser1"].GetState(),
		)
		assert.Nil(t, ds.idpToBindings["foo"]["browser1"].GetRevokedAt())

		ds.deleteIDPSession("unknown")
		assert.NotContains(t, ds.idpToBindings, "unknown")
	})

	t.Run("records", func(t *testing.T) {
		ds := newDataStore(time.Now)

		sess := databroker.NewRecord(&session.Session{Id: "browser1"})
		usr := databroker.NewRecord(&user.User{Id: "userID"})

		ds.addRecord(sess)
		ds.addRecord(usr)

		_, ok := ds.recordSet.Get("type.googleapis.com/session.Session", "browser1")
		assert.True(t, ok)
		_, ok = ds.recordSet.Get("type.googleapis.com/user.User", "userID")
		assert.True(t, ok)

		ds.addRecord(databroker.NewRecord(&session.Session{Id: "browser1", UserId: "userID"}))
		assert.Len(t, ds.recordSet["type.googleapis.com/session.Session"], 1)

		ds.deleteRecord(sess)
		_, ok = ds.recordSet.Get("type.googleapis.com/session.Session", "browser1")
		assert.False(t, ok)

		ds.deleteRecord(sess)
		ds.deleteRecord(databroker.NewRecord(&oauth21.MCPRefreshToken{Id: "mcp-client-1"}))
		_, ok = ds.recordSet.Get("type.googleapis.com/user.User", "userID")
		assert.True(t, ok)
	})

	t.Run("reset", func(t *testing.T) {
		ds := newDataStore(time.Now)

		ds.putIDPSession(&idpsession.IDPSession{Id: "foo"})
		ds.updateMapping(&idpsession.Binding{
			Id:           "browser1",
			IdpSessionId: "foo",
			TypeUrl:      "type.googleapis.com/session.Session",
		})
		ds.addRecord(databroker.NewRecord(&session.Session{Id: "browser1"}))

		ds.reset()

		assert.Empty(t, ds.idpSessions)
		assert.Empty(t, ds.idpToBindings)
		assert.Empty(t, ds.recordSet)
	})
}
