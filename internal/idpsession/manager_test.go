package idpsession_test

import (
	context "context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	oauth2 "golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/idpsession"
	oauth21 "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestIDPSessionManager(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		testIDPStoreCreate(t, func(t *testing.T) (idpsession.Manager, databroker.DataBrokerServiceClient) {
			client := testutil.NewTestDatabroker(t)

			clientB := databroker.NewStaticClientGetter(client)
			store := idpsession.NewManager(clientB, newTestGetAuthenticator(t))
			return store, client
		})
	})

	t.Run("refresh", func(t *testing.T) {
		testIDPStoreRefresh(t, func(t *testing.T) (idpsession.Manager, databroker.DataBrokerServiceClient, func(context.Context, string) (identity.Authenticator, error)) {
			client := testutil.NewTestDatabroker(t)

			clientB := databroker.NewStaticClientGetter(client)
			getAuth := newTestGetAuthenticator(t)
			store := idpsession.NewManager(clientB, getAuth)
			return store, client, getAuth
		})
	})

	t.Run("revoke", func(t *testing.T) {
		testIDPStoreRevoke(t, func(t *testing.T) (idpsession.Manager, databroker.DataBrokerServiceClient, func(context.Context, string) (identity.Authenticator, error)) {
			client := testutil.NewTestDatabroker(t)

			clientB := databroker.NewStaticClientGetter(client)
			getAuth := newTestGetAuthenticator(t)
			store := idpsession.NewManager(clientB, getAuth)
			return store, client, getAuth
		})
	})
}

func testToken(refreshToken string) *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  "access-" + refreshToken,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		Expiry:       time.Now().Add(time.Hour),
	}
}

func getIDPSession(t *testing.T, client databroker.DataBrokerServiceClient, id idpsession.ID) (*databroker.Record, *oauth21.IDPSession) {
	t.Helper()
	resp, err := client.Get(t.Context(), &databroker.GetRequest{
		Type: protoutil.GetTypeURL(&oauth21.IDPSession{}),
		Id:   id.RecordID(),
	})
	require.NoError(t, err)
	got := &oauth21.IDPSession{}
	require.NoError(t, resp.GetRecord().GetData().UnmarshalTo(got))
	return resp.GetRecord(), got
}

func assertState(
	t *testing.T,
	idpSess *oauth21.IDPSession,
	state oauth21.UpstreamIdPSessionState,
	details string,
) {
	t.Helper()

	assert.Equal(t, state.String(), idpSess.GetState().GetState().String(), "mismatched idp session state")
	assert.Contains(t, idpSess.GetState().GetDetails(), details)
}
