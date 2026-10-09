package idpsession

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	oauth21 "github.com/pomerium/pomerium/internal/oauth21/gen"
	dtestutil "github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

func (r *synchronizedReconciler) isReady() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ready
}

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
	authGetter := func(_ context.Context, _ string) (identity.Authenticator, error) {
		return authenticator, nil
	}

	mgr := NewIdentityManagerV2(databroker.NewStaticClientGetter(client), authGetter, WithReconcileInterval(time.Millisecond*50))
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
		UserId:     "bob",
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
	bindingsAndRecords = append(bindingsAndRecords, idpsession.NewBoundRecords(
		idpSess.Id, "bob", idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER, nil,
		&session.Session{
			Id:        "sessionA",
			UserId:    "bob",
			ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		},
	)...)

	bindingsAndRecords = append(bindingsAndRecords, idpsession.NewBoundRecords(
		idpSess.Id, "bob", idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER, nil,
		&session.Session{
			Id:        "sessionB",
			UserId:    "bob",
			ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		},
	)...)

	bindingsAndRecords = append(bindingsAndRecords, idpsession.NewBoundRecords(
		idpSess.Id, "bob", idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER, nil,
		&session.Session{
			Id:        "sessionC",
			UserId:    "bob",
			ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		},
	)...)

	bindingsAndRecords = append(bindingsAndRecords, idpsession.NewBoundRecords(
		idpSess.Id, "bob", idpsession.BindingProtocol_BINDING_PROTOCOL_MCP, nil,
		&oauth21.MCPRefreshToken{
			Id:        "token",
			UserId:    "bob",
			ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		},
	)...)

	_, err = client.Put(t.Context(), &databroker.PutRequest{
		Records: bindingsAndRecords,
	})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		get := func(message interface {
			proto.Message
			GetId() string
		},
		) bool {
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
			assert.Equal(collect, idpSess.GetIdToken().GetIssuer(), sessB.GetIdToken().GetIssuer())
			assert.Equal(collect, idpSess.GetOauthToken().GetAccessToken(), sessB.GetOauthToken().GetAccessToken())
			email := sessB.GetClaims()["email"].GetValues()
			if assert.NotEmpty(collect, email) {
				assert.Equal(collect, "bob@example.com", email[0].GetStringValue())
			}
		}

		sessC := &session.Session{Id: "sessionC"}
		if get(sessC) {
			assert.Equal(collect, idpSess.GetIdToken().GetIssuer(), sessC.GetIdToken().GetIssuer())
			assert.Equal(collect, idpSess.GetOauthToken().GetAccessToken(), sessC.GetOauthToken().GetAccessToken())
			email := sessC.GetClaims()["email"].GetValues()
			if assert.NotEmpty(collect, email) {
				assert.Equal(collect, "bob@example.com", email[0].GetStringValue())
			}
		}

		mcp := &oauth21.MCPRefreshToken{Id: "token"}
		if get(mcp) {
			assert.Equal(collect, idpSess.GetOauthToken().GetRefreshToken(), mcp.GetUpstreamRefreshToken())
		}
	}, 5*time.Second, 10*time.Millisecond)

	_, revokeBerr := storage.DeleteDataBrokerRecord(t.Context(), client, "type.googleapis.com/idpsession.Binding", "sessionB")
	require.NoError(t, revokeBerr)

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, err := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/session.Session",
			Id:   "sessionB",
		})
		assert.Equal(collect, codes.NotFound, status.Code(err), "expect session to be deleted")
		_, err2 := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/idpsession.Binding",
			Id:   "sessionB",
		})
		assert.Equal(collect, codes.NotFound, status.Code(err2), "expect binding to be deleted")
	}, 5*time.Second, 10*time.Millisecond, "revoking binding should delete dependent records")

	_, delErr3 := storage.DeleteDataBrokerRecord(t.Context(), client, "type.googleapis.com/session.Session", "sessionC")
	require.NoError(t, delErr3)

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, err := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/session.Session",
			Id:   "sessionC",
		})
		assert.Equal(collect, codes.NotFound, status.Code(err), "expect session to be deleted")
		_, err2 := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/idpsession.Binding",
			Id:   "sessionC",
		})
		assert.Equal(collect, codes.NotFound, status.Code(err2), "expect binding to be deleted")
	}, 5*time.Second, 10*time.Millisecond, "deleting a dependent should revoke its binding")

	// invalidating the IDP session should clean up remaining dependencies.
	_, revokeErr := storage.DeleteDataBrokerRecord(t.Context(), client, idpSessionTypeURL, "foo")
	require.NoError(t, revokeErr)

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, errSess := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/session.Session",
			Id:   "sessionA",
		})
		assert.Equal(collect, codes.NotFound, status.Code(errSess), "session should be deleted after idpsession is deleted")

		_, errTok := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/oauth21.MCPRefreshToken",
			Id:   "token",
		})
		assert.Equal(collect, codes.NotFound, status.Code(errTok), "mcp token should be deleted after idpsession is deleted")
	}, 5*time.Second, 10*time.Millisecond)
}

func TestIdentityManagerRevokedCleanUp(t *testing.T) {
	now := time.Now()
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
	authGetter := func(_ context.Context, _ string) (identity.Authenticator, error) {
		return authenticator, nil
	}
	timeMu := sync.Mutex{}
	ts := now

	mgr := NewIdentityManagerV2(databroker.NewStaticClientGetter(client), authGetter, WithReconcileInterval(time.Millisecond*50), WithNow(func() time.Time {
		timeMu.Lock()
		defer timeMu.Unlock()
		return ts
	}))
	ctxca, ca := context.WithCancel(t.Context())
	t.Cleanup(ca)
	go mgr.Run(ctxca)

	// there is a chance that while the SyncLatest stream is running that a create+delete operation
	// ends up missing the delete tombstone, which means depedent records of a deleted binding could
	// never be cleaned up. This could lead to legitimate bugs.
	assert.Eventually(t, func() bool {
		return mgr.identReconciler.isReady()
	}, time.Second*5, time.Millisecond)

	claims, err := structpb.NewStruct(map[string]any{
		"email":  "bob@example.com",
		"groups": []any{"engineering", "developers"},
	})
	require.NoError(t, err)
	idpSess := &idpsession.IDPSession{
		Id:         "foo",
		UserId:     "bob",
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
	bindingsAndRecords = append(bindingsAndRecords, idpsession.NewBoundRecords(
		idpSess.Id, "bob", idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER, nil,
		&session.Session{
			Id:        "sessionA",
			UserId:    "bob",
			ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		},
	)...)

	bindingsAndRecords = append(bindingsAndRecords, idpsession.NewBoundRecords(
		idpSess.Id, "bob", idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER, nil,
		&session.Session{
			Id:        "sessionB",
			UserId:    "bob",
			ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		},
	)...)

	bindingsAndRecords = append(bindingsAndRecords, idpsession.NewBoundRecords(
		idpSess.Id, "bob", idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER, nil,
		&session.Session{
			Id:        "sessionC",
			UserId:    "bob",
			ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		},
	)...)

	bindingsAndRecords = append(bindingsAndRecords, idpsession.NewBoundRecords(
		idpSess.Id, "bob", idpsession.BindingProtocol_BINDING_PROTOCOL_MCP, nil,
		&oauth21.MCPRefreshToken{
			Id:        "token",
			UserId:    "bob",
			ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		},
	)...)

	_, putErr := client.Put(t.Context(), &databroker.PutRequest{
		Records: bindingsAndRecords,
	})
	require.NoError(t, putErr)

	_, revokeBerr := storage.DeleteDataBrokerRecord(t.Context(), client, "type.googleapis.com/idpsession.Binding", "sessionB")
	require.NoError(t, revokeBerr)
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, err := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/session.Session",
			Id:   "sessionB",
		})
		assert.Equal(collect, codes.NotFound, status.Code(err), "expect session to be deleted")
		_, err2 := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/idpsession.Binding",
			Id:   "sessionB",
		})
		assert.Equal(collect, codes.NotFound, status.Code(err2), "expect binding to be deleted")
	}, 5*time.Second, 100*time.Millisecond, "revoking binding should delete dependent records")

	// deleting the idpsession revokes everything bound to it

	_, revokeErr := storage.DeleteDataBrokerRecord(t.Context(), client, idpSessionTypeURL, "foo")
	require.NoError(t, revokeErr)

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		for _, rec := range bindingsAndRecords {
			_, err := client.Get(t.Context(), &databroker.GetRequest{
				Type: rec.GetData().GetTypeUrl(),
				Id:   rec.GetId(),
			})
			assert.Equal(collect, codes.NotFound, status.Code(err),
				fmt.Sprintf("expected %s-%s to be deleted", rec.GetData().GetTypeUrl(), rec.GetId()))
		}
	}, 5*time.Second, 100*time.Millisecond)
}
