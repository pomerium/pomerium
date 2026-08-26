package idpsession_test

// import (
// 	"sync"
// 	"testing"
// 	"testing/synctest"

// 	"github.com/stretchr/testify/assert"
// 	"github.com/stretchr/testify/require"

// 	oauth21 "github.com/pomerium/pomerium/internal/oauth21/gen"
// 	"github.com/pomerium/pomerium/pkg/grpc/databroker"
// )

// func testIDPStoreRecreate(t *testing.T, storeF func(t *testing.T) (Manager, databroker.DataBrokerServiceClient, authenticatorGetter)) {
// 	t.Run("simple", func(t *testing.T) {
// 		store, client, _ := storeF(t)
// 		id := ID{
// 			IdpID:  "flaky",
// 			UserID: "recreate",
// 		}
// 		assert.NoError(t, store.Create(t.Context(), id, testToken("todo"), "todo"))
// 		assert.NoError(t, store.Recreate(t.Context(), id, &mockState{}))

// 		_, got := getIDPSession(t, client, id)
// 		assert.Equal(t, got.GetRefreshToken().GetGeneration(), uint64(1))
// 	})

// 	t.Run("concurrent", func(t *testing.T) {
// 		synctest.Test(t, func(t *testing.T) {
// 			store, client, _ := storeF(t)
// 			id := ID{
// 				UserID: "foo",
// 				IdpID:  "block-flaky",
// 			}

// 			assert.NoError(t, store.Create(t.Context(), id, testToken("todo"), "todo"))

// 			previousRec, previous := getIDPSession(t, client, id)

// 			wg := sync.WaitGroup{}

// 			wg.Go(func() {
// 				assert.NoError(t, store.Recreate(t.Context(), id, &mockState{}))
// 			})

// 			wg.Go(func() {
// 				assert.NoError(t, store.Recreate(t.Context(), id, &mockState{}))
// 			})

// 			synctest.Wait()

// 			wg.Wait()

// 			rec, got := getIDPSession(t, client, id)
// 			assert.Equal(t, previousRec.GetVersion()+1, rec.GetVersion(), "expected concurrent in flight operations to change records once")
// 			assert.Equal(t, previous.GetRefreshToken().GetGeneration()+1, got.GetRefreshToken().GetGeneration(), "expected concurrent in flight operations to rotate token once")
// 			assert.Equal(t, got.GetRefreshToken().GetEpoch(), uint64(0))
// 		})
// 	})

// 	t.Run("recreate idp revoked", func(t *testing.T) {
// 		store, client, getAuth := storeF(t)

// 		id := ID{
// 			UserID: "asd",
// 			IdpID:  "once",
// 		}
// 		assert.NoError(t, store.Create(t.Context(), id, testToken("todo"), "todo"))

// 		_, err := store.Refresh(t.Context(), id, &mockState{})
// 		assert.NoError(t, err)

// 		_, got := getIDPSession(t, client, id)

// 		oauthToken := FromOAuthToken(got)

// 		// manually exchange and consume the refresh token outside of the singleflight path

// 		authenticator, err := getAuth(t.Context(), id.IdpID)
// 		require.NoError(t, err)
// 		gotToken, err := authenticator.Refresh(t.Context(), oauthToken, &mockState{})
// 		require.NoError(t, err)
// 		assert.NotEqual(t, gotToken.RefreshToken, oauthToken.RefreshToken)

// 		// now try and refresh.

// 		_, err = store.Refresh(t.Context(), id, &mockState{})
// 		assert.Error(t, err)
// 		// TODO : strongly typed error?

// 		_, after := getIDPSession(t, client, id)
// 		assertState(t, after, oauth21.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID, "invalid_grant")
// 	})

// 	t.Run("recreate revoked", func(t *testing.T) {
// 		// should not work

// 		store, _, _ := storeF(t)

// 		id := ID{
// 			IdpID:  "flaky",
// 			UserID: "alex2",
// 		}
// 		assert.NoError(t, store.Create(t.Context(), id, testToken("refreshToken"), "rawIDToken"))
// 		assert.NoError(t, store.Revoke(t.Context(), id))

// 		// TODO : strongly typed error?
// 		assert.Error(t, store.Recreate(t.Context(), id, &mockState{}))
// 	})

// 	t.Run("recreate unknown", func(t *testing.T) {
// 		store, _, _ := storeF(t)
// 		id := ID{
// 			IdpID:  "flaky",
// 			UserID: "alex2",
// 		}
// 		assert.Error(t, store.Recreate(t.Context(), id, &mockState{}))
// 	})
// }
