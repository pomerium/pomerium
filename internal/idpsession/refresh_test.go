package idpsession_test

import (
	context "context"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/idpsession"
	oauth21 "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	identity "github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/manager"
)

func testIDPStoreRefresh(t *testing.T, storeF func(t *testing.T) (idpsession.Manager, databroker.DataBrokerServiceClient, func(context.Context, string) (identity.Authenticator, error))) {
	t.Run("simple", func(t *testing.T) {
		store, client, _ := storeF(t)
		id := idpsession.ID{
			IdpID:  "consume",
			UserID: "alex2",
		}
		assert.NoError(t, store.Create(t.Context(), id, testToken("todo"), "todo"))

		_, got := getIDPSession(t, client, id)

		curTok := got.GetRefreshToken().GetToken()
		assert.NotEqual(t, "", curTok)

		s := &session.Session{}
		newTok, err := store.Refresh(t.Context(), id, manager.NewSessionUnmarshaler(s))
		assert.NoError(t, err)

		// TODO : assert claims and ID Token are propagated to session.Session

		assert.NotEqual(t, curTok, newTok.RefreshToken, "token should have been rotated")

		newTok2, err := store.Refresh(t.Context(), id, manager.NewSessionUnmarshaler(s))
		assert.NoError(t, err)
		assert.NotEqual(t, curTok, newTok2.RefreshToken, "token should have been rotated")
		assert.NotEqual(t, newTok.RefreshToken, newTok2.RefreshToken, "token should have been rotated")
	})

	t.Run("concurrent", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			store, client, getAuth := storeF(t)
			id := idpsession.ID{
				UserID: "foo",
				IdpID:  "block",
			}

			assert.NoError(t, store.Create(t.Context(), id, testToken("todo"), "todo"))

			authenticator, err := getAuth(t.Context(), id.IdpID)
			require.NoError(t, err)

			previousRec, previous := getIDPSession(t, client, id)

			wg := sync.WaitGroup{}

			s := &session.Session{}

			wg.Go(func() {
				_, err := store.Refresh(t.Context(), id, manager.NewSessionUnmarshaler(s))
				assert.NoError(t, err)
			})

			wg.Go(func() {
				_, err := store.Refresh(t.Context(), id, manager.NewSessionUnmarshaler(s))
				assert.NoError(t, err)
			})

			synctest.Wait()
			authenticator.(*authMock).release <- struct{}{}

			wg.Wait()

			rec, got := getIDPSession(t, client, id)
			assert.Equal(t, previousRec.GetVersion()+1, rec.GetVersion(), "expected concurrent in flight operations to change records once")
			assert.Equal(t, previous.GetRefreshToken().GetEpoch()+1, got.GetRefreshToken().GetEpoch(), "expected concurrent in flight operations to rotate token once")
		})
	})

	t.Run("invalid flow", func(t *testing.T) {
		store, _, _ := storeF(t)
		id := idpsession.ID{
			UserID: "not_found",
			IdpID:  "normal",
		}
		s := &session.Session{}
		_, err := store.Refresh(t.Context(), id, manager.NewSessionUnmarshaler(s))
		assert.Error(t, err)
	})

	t.Run("idp revoked", func(t *testing.T) {
		store, client, getAuth := storeF(t)

		id := idpsession.ID{
			UserID: "asd",
			IdpID:  "once",
		}
		assert.NoError(t, store.Create(t.Context(), id, testToken("todo"), "todo"))

		s := &session.Session{}
		_, err := store.Refresh(t.Context(), id, manager.NewSessionUnmarshaler(s))
		assert.NoError(t, err)

		_, got := getIDPSession(t, client, id)

		oauthToken := idpsession.FromOAuthToken(got)

		// manually exchange and consume the refresh token outside of the singleflight path

		authenticator, err := getAuth(t.Context(), id.IdpID)
		require.NoError(t, err)
		gotToken, err := authenticator.Refresh(t.Context(), oauthToken, s)
		assert.NoError(t, err)
		assert.NotEqual(t, gotToken.RefreshToken, oauthToken.RefreshToken)

		// now try and refresh.

		_, err = store.Refresh(t.Context(), id, s)
		assert.Error(t, err)

		_, after := getIDPSession(t, client, id)
		assertState(t, after, oauth21.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID, "invalid_grant")
	})

	t.Run("consistent communication error", func(t *testing.T) {
		store, client, _ := storeF(t)
		id := idpsession.ID{
			UserID: "grrr",
			IdpID:  "error",
		}

		assert.NoError(t, store.Create(t.Context(), id, testToken("todo"), "todo"))

		s := &session.Session{}
		_, err := store.Refresh(t.Context(), id, manager.NewSessionUnmarshaler(s))
		assert.Error(t, err)

		_, after := getIDPSession(t, client, id)
		assertState(t, after, oauth21.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_VALID, "")
	})
}
