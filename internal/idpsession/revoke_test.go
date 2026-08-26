package idpsession_test

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/idpsession"
	oauth21 "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/manager"
)

func testIDPStoreRevoke(t *testing.T, storeF func(t *testing.T) (idpsession.Manager, databroker.DataBrokerServiceClient, func(context.Context, string) (identity.Authenticator, error))) {
	t.Run("simple", func(t *testing.T) {
		store, client, _ := storeF(t)

		id := idpsession.ID{
			UserID: "asd",
			IdpID:  "normal",
		}

		assert.NoError(t, store.Create(t.Context(), id, testToken("tok"), "asd"))
		assert.NoError(t, store.Revoke(t.Context(), id))

		_, got := getIDPSession(t, client, id)
		assertState(t, got, oauth21.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID, "revoked")
	})

	t.Run("many revoke", func(t *testing.T) {
		store, client, _ := storeF(t)

		id := idpsession.ID{
			UserID: "asd",
			IdpID:  "normal",
		}

		assert.NoError(t, store.Create(t.Context(), id, testToken("tok"), "asd"))
		assert.NoError(t, store.Revoke(t.Context(), id))

		_, got := getIDPSession(t, client, id)
		assertState(t, got, oauth21.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID, "revoked")

		assert.NoError(t, store.Revoke(t.Context(), id))
	})

	t.Run("create after revoke", func(t *testing.T) {
		// should succeed
		store, client, _ := storeF(t)

		id := idpsession.ID{
			UserID: "asd",
			IdpID:  "normal",
		}

		assert.NoError(t, store.Create(t.Context(), id, testToken("tok"), "asd"))
		assert.NoError(t, store.Revoke(t.Context(), id))

		rec, got := getIDPSession(t, client, id)
		assertState(t, got, oauth21.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID, "revoked")

		assert.NoError(t, store.Create(t.Context(), id, testToken("todo"), "todo"))
		rec2, got2 := getIDPSession(t, client, id)
		assert.Greater(t, rec2.GetVersion(), rec.GetVersion())
		assertState(t, got2, oauth21.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_VALID, "")
	})

	t.Run("refresh after revoke", func(t *testing.T) {
		// should succeed
		store, client, _ := storeF(t)

		id := idpsession.ID{
			UserID: "asd",
			IdpID:  "normal",
		}
		s := &session.Session{}

		assert.NoError(t, store.Create(t.Context(), id, testToken("tok"), "asd"))
		assert.NoError(t, store.Revoke(t.Context(), id))

		_, got := getIDPSession(t, client, id)
		assertState(t, got, oauth21.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID, "revoked")

		_, refreshErr := store.Refresh(t.Context(), id, manager.NewSessionUnmarshaler(s))
		assert.Error(t, refreshErr)
	})

	t.Run("revoke during refresh", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			store, client, getAuth := storeF(t)
			id := idpsession.ID{UserID: "asd", IdpID: "block"}
			require.NoError(t, store.Create(t.Context(), id, testToken("tik"), "ttttttoken"))

			authenticator, err := getAuth(t.Context(), id.IdpID)
			require.NoError(t, err)
			mock := authenticator.(*authMock)

			s := &session.Session{}
			var wg sync.WaitGroup
			wg.Go(func() {
				_, err := store.Refresh(t.Context(), id, manager.NewSessionUnmarshaler(s))
				assert.ErrorContains(t, err, "invalid_grant")
			})

			// refresh owns the singleflight key and is parked in the idp call,
			// having read a record that is still valid
			synctest.Wait()

			wg.Go(func() {
				assert.NoError(t, store.Revoke(t.Context(), id))
			})

			// authenticator.Revoke runs outside the singleflight, so the grant dies
			// before refresh presents the token; Revoke then parks on the held key
			<-mock.revokeCalls
			synctest.Wait()

			mock.release <- struct{}{}
			wg.Wait()

			// the shared Revoke never runs its own callback, so the record carries the
			// invalidation written by the refresh path
			_, got := getIDPSession(t, client, id)
			assertState(t, got, oauth21.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID, "invalid_grant")
		})
	})

	// t.Run("recreate after revoke", func(t *testing.T) {
	// 	store, client := storeF(t)

	// 	id := ID{
	// 		UserID: "asd",
	// 		IdpID:  "normal",
	// 	}

	// 	assert.NoError(t, store.Create(t.Context(), id, testToken("tok"), "asd"))
	// 	assert.NoError(t, store.Revoke(t.Context(), id))

	// 	_, got := getIDPSession(t, client, id)
	// 	assertState(t, got, oauth21.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID, "revoked")

	// 	recreateErr := store.Recreate(t.Context(), id, &mockState{})
	// 	// TODO : strongly typed error?
	// 	assert.Error(t, recreateErr)
	// })
}
