package idpsession

import (
	"testing"

	oauth21 "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDataStoreChangeSet(t *testing.T) {
	t.Run("propagate all", func(t *testing.T) {
		ds := newDataStore()

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

		ds.updateMapping(&idpsession.IDPSessionBinding{
			Id:           "browser1",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/session.Session",
		})

		ds.updateMapping(&idpsession.IDPSessionBinding{
			Id:           "browser2",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/session.Session",
		})

		// TODO : should we enforce a one-to-one mapping here?
		ds.updateMapping(&idpsession.IDPSessionBinding{
			Id:           "userID",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/user.User",
		})

		ds.updateMapping(&idpsession.IDPSessionBinding{
			Id:           "mcp-client-1",
			IdpSessionId: idpSessionID,
			TypeUrl:      "type.googleapis.com/oauth21.MCPRefreshToken",
		})

		ds.updateMapping(&idpsession.IDPSessionBinding{
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

	})
}

func TestDataStore(t *testing.T) {
	t.Run("idpsession", func(t *testing.T) {
		ds := newDataStore()
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

		ds.deleteAllIDPSessions()
		assert.Len(t, ds.idpSessions, 0)

	})

	t.Run("binding", func(t *testing.T) {

	})

	t.Run("records", func(t *testing.T) {

	})
}
