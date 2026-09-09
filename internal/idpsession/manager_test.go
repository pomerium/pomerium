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
	"github.com/pomerium/pomerium/internal/testutil"
	dtestutil "github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
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

	require.NoError(t, idpsession.RevokeBinding(t.Context(), client, "sessionB"))

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, err := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/session.Session",
			Id:   "sessionB",
		})
		assert.Equal(collect, codes.NotFound, status.Code(err), "expect session to be deleted")
		resp, err2 := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/idpsession.Binding",
			Id:   "sessionB",
		})
		if assert.NoError(collect, err2) {
			binding := new(idpsession.Binding)
			if assert.NoError(collect, resp.GetRecord().GetData().UnmarshalTo(binding)) {
				assert.Equal(collect, idpsession.BindingState_BindingState_REVOKED, binding.GetState())
			}
		}
	}, 5*time.Second, 10*time.Millisecond, "revoking binding should delete dependent records")

	// should NEVER delete user record

	require.NoError(t, idpsession.RevokeBinding(t.Context(), client, "bob"))

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
		resp, err2 := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/idpsession.Binding",
			Id:   "sessionC",
		})
		if assert.NoError(collect, err2, "authoritative binding should be retained") {
			binding := new(idpsession.Binding)
			if assert.NoError(collect, resp.GetRecord().GetData().UnmarshalTo(binding)) {
				assert.Equal(collect, idpsession.BindingState_BindingState_ACTIVE, binding.GetState())
			}
		}
	}, 5*time.Second, 10*time.Millisecond, "deleting a dependent should not delete its authoritative binding")

	// invalidating the IDP session should clean up remaining dependencies.
	require.NoError(t, idpsession.RevokeIDPSession(t.Context(), client, "foo", "revoked by user"))

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

	_, putErr := client.Put(t.Context(), &databroker.PutRequest{
		Records: bindingsAndRecords,
	})
	require.NoError(t, putErr)

	require.NoError(t, idpsession.RevokeBinding(t.Context(), client, "sessionB"))
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, err := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/session.Session",
			Id:   "sessionB",
		})
		assert.Equal(collect, codes.NotFound, status.Code(err), "expect session to be deleted")
		resp, err2 := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/idpsession.Binding",
			Id:   "sessionB",
		})
		if assert.NoError(collect, err2) {
			binding := new(idpsession.Binding)
			if assert.NoError(collect, resp.GetRecord().GetData().UnmarshalTo(binding)) {
				assert.Equal(collect, idpsession.BindingState_BindingState_REVOKED, binding.GetState())
			}
		}
	}, 5*time.Second, 10*time.Millisecond, "revoking binding should delete dependent records")

	// advance time, make sure binding gets revoked.
	timeMu.Lock()
	ts = now.Add(time.Hour * 2)
	timeMu.Unlock()

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		_, err := client.Get(t.Context(), &databroker.GetRequest{
			Type: "type.googleapis.com/idpsession.Binding",
			Id:   "sessionB",
		})
		assert.Equal(collect, codes.NotFound, status.Code(err), "expect binding to be deleted")
	}, 5*time.Second, 10*time.Millisecond, "revoked binding should be eventually cleaned up")

	// go back in time
	timeMu.Lock()
	ts = time.Now()
	timeMu.Unlock()

	require.NoError(t, idpsession.RevokeIDPSession(t.Context(), client, "foo", "user revoked"))

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		for _, rec := range bindingsAndRecords {
			if rec.GetId() == "sessionB" {
				// already cleaned up by the binding revocation above.
				continue
			}
			if rec.GetData().GetTypeUrl() == "type.googleapis.com/idpsession.IDPSession" {
				_, err := client.Get(t.Context(), &databroker.GetRequest{
					Type: rec.GetData().GetTypeUrl(),
					Id:   rec.GetId(),
				})
				assert.NoError(collect, err, "idpsession should not be cleaned up immediately")
				continue
			}
			if rec.GetData().GetTypeUrl() == "type.googleapis.com/user.User" {
				_, err := client.Get(t.Context(), &databroker.GetRequest{
					Type: rec.GetData().GetTypeUrl(),
					Id:   rec.GetId(),
				})
				assert.NoError(collect, err, "user records should never be deleted")
				continue
			}

			if rec.GetData().GetTypeUrl() == "type.googleapis.com/idpsession.Binding" {
				got, err := client.Get(t.Context(), &databroker.GetRequest{
					Type: rec.GetData().GetTypeUrl(),
					Id:   rec.GetId(),
				})
				assert.NoError(collect, err, "bindings should not be cleaned up immediately")
				binding := &idpsession.Binding{}
				assert.NoError(collect, got.GetRecord().GetData().UnmarshalTo(binding))
				assert.Equal(collect, idpsession.BindingState_BindingState_REVOKED.String(), binding.State.String())
				continue
			}
			_, err := client.Get(t.Context(), &databroker.GetRequest{
				Type: rec.GetData().GetTypeUrl(),
				Id:   rec.GetId(),
			})
			assert.Error(collect, err)
			assert.Equal(collect, codes.NotFound, status.Code(err), fmt.Sprintf("expected %s-%s to be deleted", rec.GetData().GetTypeUrl(), rec.GetId()))
		}
	}, 5*time.Second, 10*time.Millisecond)

	// advance time

	timeMu.Lock()
	ts = time.Now().Add(time.Hour * 2)
	timeMu.Unlock()

	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		for _, rec := range bindingsAndRecords {
			if rec.GetData().GetTypeUrl() == "type.googleapis.com/user.User" {
				_, err := client.Get(t.Context(), &databroker.GetRequest{
					Type: rec.GetData().GetTypeUrl(),
					Id:   rec.GetId(),
				})
				assert.NoError(collect, err, "userinfo should never be deleted")
				continue
			}
			// all the other records should be cleaned up now
			_, err := client.Get(t.Context(), &databroker.GetRequest{
				Type: rec.GetData().GetTypeUrl(),
				Id:   rec.GetId(),
			})

			assert.Error(collect, err)
			assert.Equal(collect, codes.NotFound, status.Code(err))
		}
	}, 5*time.Second, 10*time.Millisecond)
}
