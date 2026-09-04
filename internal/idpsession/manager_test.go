package idpsession

import (
	"context"
	"testing"
	"time"

	oauth21 "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/internal/testutil"
	dtestutil "github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestIdentityManagerHappyPath(t *testing.T) {
	now := time.Now()
	zerolog.SetGlobalLevel(zerolog.Disabled)
	client := dtestutil.NewTestDatabroker(t)
	authenticator := &mockAuthenticator{
		refreshResult: &oauth2.Token{
			AccessToken:  "foo",
			TokenType:    "Bearer",
			RefreshToken: "foo",
			Expiry:       now.Add(time.Hour),
		},
		updateUserInfoError: nil,
		refreshError:        nil,
	}
	authGetter := func(ctx context.Context, idpID string) (identity.Authenticator, error) {
		return authenticator, nil
	}

	mgr := NewIdentityManager(databroker.NewStaticClientGetter(client), authGetter, WithReconcileInterval(time.Millisecond*50))
	ctxca, ca := context.WithCancel(t.Context())
	t.Cleanup(ca)
	go mgr.Run(ctxca)

	claims, err := structpb.NewStruct(map[string]any{
		"email":  "bob@example.com",
		"groups": []any{"engineering", "developers"},
	})
	require.NoError(t, err)

	idpSess := &idpsession.IDPSession{
		Id:         "foo",
		RawIdToken: "foo",
		IdToken: &idpsession.IDToken{
			Issuer:    "foo",
			Subject:   "foo",
			ExpiresAt: timestamppb.New(now.Add(time.Hour)),
			IssuedAt:  timestamppb.New(now),
		},
		OauthToken: &idpsession.OAuthToken{
			AccessToken:  "foo",
			TokenType:    "Bearer",
			ExpiresAt:    timestamppb.New(now.Add(time.Hour)),
			RefreshToken: "foo",
		},
		Claims: claims,
	}

	bindingsAndRecords := []*databroker.Record{
		databroker.NewRecord(idpSess),
	}
	bindingsAndRecords = append(bindingsAndRecords, newSessionWithBinding(&session.Session{
		Id:        "sessionA",
		UserId:    "bob",
		ExpiresAt: timestamppb.New(now.Add(time.Hour)),
	}, idpSess.Id)...)

	bindingsAndRecords = append(bindingsAndRecords, newSessionWithBinding(&session.Session{
		Id:        "sessionB",
		UserId:    "bob",
		ExpiresAt: timestamppb.New(now.Add(time.Hour)),
	}, idpSess.Id)...)

	bindingsAndRecords = append(bindingsAndRecords, newSessionWithBinding(&session.Session{
		Id:        "sessionC",
		UserId:    "bob",
		ExpiresAt: timestamppb.New(now.Add(time.Hour)),
	}, idpSess.Id)...)

	bindingsAndRecords = append(bindingsAndRecords, newUserWithBinding(&user.User{
		Id: "bob",
	}, idpSess.Id)...)

	bindingsAndRecords = append(bindingsAndRecords, newMCPWithBinding(&oauth21.MCPRefreshToken{
		Id:        "token",
		UserId:    "bob",
		ExpiresAt: timestamppb.New(now.Add(time.Hour)),
	}, idpSess.Id)...)

	_, err = client.Put(t.Context(), &databroker.PutRequest{
		Records: bindingsAndRecords,
	})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		get := func(message interface {
			proto.Message
			GetId() string
		}) bool {
			resp, err := client.Get(t.Context(), &databroker.GetRequest{
				Type: protoutil.GetTypeURL(message),
				Id:   message.GetId(),
			})
			if !assert.NoError(collect, err) {
				return false
			}
			return assert.NoError(collect, resp.GetRecord().GetData().UnmarshalTo(message))
		}

		sessA := &session.Session{Id: "sessionA"}
		if get(sessA) {
			assert.Equal(collect, idpSess.GetIdToken().GetIssuer(), sessA.GetIdToken().GetIssuer())
			assert.Equal(collect, idpSess.GetOauthToken().GetAccessToken(), sessA.GetOauthToken().GetAccessToken())
			email := sessA.GetClaims()["email"].GetValues()
			if assert.NotEmpty(collect, email) {
				assert.Equal(collect, "bob@example.com", email[0].GetStringValue())
			}
		}

		sessB := &session.Session{Id: "sessionB"}
		if get(sessB) {
			assert.Equal(collect, idpSess.GetIdToken().GetIssuer(), sessA.GetIdToken().GetIssuer())
			assert.Equal(collect, idpSess.GetOauthToken().GetAccessToken(), sessA.GetOauthToken().GetAccessToken())
			email := sessA.GetClaims()["email"].GetValues()
			if assert.NotEmpty(collect, email) {
				assert.Equal(collect, "bob@example.com", email[0].GetStringValue())
			}
		}

		sessC := &session.Session{Id: "sessionC"}
		if get(sessC) {
			assert.Equal(collect, idpSess.GetIdToken().GetIssuer(), sessA.GetIdToken().GetIssuer())
			assert.Equal(collect, idpSess.GetOauthToken().GetAccessToken(), sessA.GetOauthToken().GetAccessToken())
			email := sessA.GetClaims()["email"].GetValues()
			if assert.NotEmpty(collect, email) {
				assert.Equal(collect, "bob@example.com", email[0].GetStringValue())
			}
		}

		u := &user.User{Id: "bob"}
		if get(u) {
			email := u.GetClaims()["email"].GetValues()
			if assert.NotEmpty(collect, email) {
				assert.Equal(collect, "bob@example.com", email[0].GetStringValue())
			}
			assert.Len(collect, u.GetClaims()["groups"].GetValues(), 2)
		}

		mcp := &oauth21.MCPRefreshToken{Id: "token"}
		if get(mcp) {
			assert.Equal(collect, idpSess.GetOauthToken().GetRefreshToken(), mcp.GetUpstreamRefreshToken())
		}
	}, 5*time.Second, 10*time.Millisecond)

	// deleting the binding for sessionB should result in sessionA being deleted.

	_, delErr := storage.DeleteDataBrokerRecord(t.Context(), client, "type.googleapis.com/idpsession.IDPSessionBinding", "sessionB")
	require.NoError(t, delErr)

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, err := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/session.Session",
			Id:   "sessionB",
		})
		assert.Equal(collect, codes.NotFound, status.Code(err), "expect session to be deleted")
		_, err2 := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/idpsession.IDPSessionBinding",
			Id:   "sessionB",
		})
		assert.Equal(collect, codes.NotFound, status.Code(err2), "expect binding to be deleted")

	}, 5*time.Second, 10*time.Millisecond, "deleting binding should delete dependent records")

	// should NEVER delete user record

	_, delErr2 := storage.DeleteDataBrokerRecord(t.Context(), client, "type.googleapis.com/idpsession.IDPSessionBinding", "bob")
	require.NoError(t, delErr2)

	testutil.AssertConsistentlyWithT(t, func(c assert.TestingT) {
		_, err := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/user.User",
			Id:   "bob",
		})
		assert.NoError(c, err)
	}, 5*time.Second, 5*time.Millisecond)

	// we may not want to keep this behaviour.

	_, delErr3 := storage.DeleteDataBrokerRecord(t.Context(), client, "type.googleapis.com/session.Session", "sessionC")
	require.NoError(t, delErr3)

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, err := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/session.Session",
			Id:   "sessionC",
		})
		assert.Equal(collect, codes.NotFound, status.Code(err), "expect session to be deleted")
		_, err2 := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/idpsession.IDPSessionBinding",
			Id:   "sessionC",
		})
		assert.Equal(collect, codes.NotFound, status.Code(err2), "expect binding to be deleted")
	}, 5*time.Second, 10*time.Millisecond, "deleting dependent record should result in binding being cleaned up")

	// deleting the IDP session should clean up remaining dependencies.

	_, delErr4 := storage.DeleteDataBrokerRecord(t.Context(), client, "type.googleapis.com/idpsession.IDPSession", "foo")
	require.NoError(t, delErr4)

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		// _, err :=
		_, errSess := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/session.Session",
			Id:   "sessionA",
		})
		assert.Equal(collect, codes.NotFound, status.Code(errSess), "session should be deleted after idpsession is deleted")

		_, errTok := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/oauth21.MCPRefreshToken",
			Id:   "tok",
		})
		assert.Equal(collect, codes.NotFound, status.Code(errTok), "mcp token should be deleted after idpsession is deleted")

	}, 5*time.Second, 10*time.Millisecond)

	// verify again that user should NEVER be deleted

	testutil.AssertConsistentlyWithT(t, func(c assert.TestingT) {
		_, err := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/user.User",
			Id:   "bob",
		})
		assert.NoError(c, err)
	}, 5*time.Second, 5*time.Millisecond)

}
