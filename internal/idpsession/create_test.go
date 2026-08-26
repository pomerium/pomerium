package idpsession_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func testIDPStoreCreate(t *testing.T, storeF func(t *testing.T) (idpsession.Manager, databroker.DataBrokerServiceClient)) {
	t.Run("simple", func(t *testing.T) {
		store, _ := storeF(t)
		err := store.Create(t.Context(), idpsession.ID{
			UserID: "userID1",
			IdpID:  "normal",
		}, testToken("refreshTok"), "idTok")
		assert.NoError(t, err)
	})

	t.Run("pre-existing", func(t *testing.T) {
		t.Skip("unimplemented behaviour needs to be decided")
		// this should fail or should it index multiple session?
		store, _ := storeF(t)
		id := idpsession.ID{
			IdpID:  "normal",
			UserID: "alex1",
		}
		assert.NoError(t, store.Create(t.Context(), id, testToken("refreshToken"), "rawIDToken"))
		assert.Error(t, store.Create(t.Context(), id, testToken("refreshToken"), "rawIDToken"))
	})

	t.Run("create after revoke", func(t *testing.T) {
		// this should work.
		store, _ := storeF(t)

		id := idpsession.ID{
			IdpID:  "normal",
			UserID: "alex2",
		}
		assert.NoError(t, store.Create(t.Context(), id, testToken("refreshToken"), "rawIDToken"))
		assert.NoError(t, store.Revoke(t.Context(), id))
		assert.NoError(t, store.Create(t.Context(), id, testToken("refreshToken"), "rawIDToken"))
	})
}
