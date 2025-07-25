package manager

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/testutil/matchers"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/mock_databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type mockAuthenticator struct {
	identity.Authenticator

	refreshResult       *oauth2.Token
	refreshError        error
	revokeError         error
	updateUserInfoError error
}

func (mock *mockAuthenticator) Refresh(_ context.Context, _ *oauth2.Token, _ identity.State) (*oauth2.Token, error) {
	return mock.refreshResult, mock.refreshError
}

func (mock *mockAuthenticator) Revoke(_ context.Context, _ *oauth2.Token) error {
	return mock.revokeError
}

func (mock *mockAuthenticator) UpdateUserInfo(_ context.Context, _ *oauth2.Token, _ any) error {
	return mock.updateUserInfoError
}

func TestRefreshSession(t *testing.T) {
	validSession := func() *session.Session {
		iat := time.Now()
		return &session.Session{
			Id:        "session-1",
			UserId:    "user-1",
			IssuedAt:  timestamppb.New(iat),
			ExpiresAt: timestamppb.New(iat.Add(24 * time.Hour)),
			OauthToken: &session.OAuthToken{
				AccessToken:  "fake-access-token",
				RefreshToken: "fake-refresh-token",
			},
		}
	}

	t.Run("session does not exist", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		mgr := New(WithDataBrokerClient(client))
		mgr.refreshSession(t.Context(), "session-1")
		// no databroker calls expected
	})
	t.Run("no authenticator", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)

		mgr := New(
			WithDataBrokerClient(client),
			WithGetAuthenticator(func(_ context.Context, _ string) (identity.Authenticator, error) {
				return nil, errors.New("no authenticator")
			}),
		)

		sess := validSession()
		expectSessionDelete(client, sess)

		mgr.onUpdateSession(t.Context(), sess)
		mgr.refreshSession(t.Context(), "session-1")
	})
	t.Run("session expired", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		authenticator := &mockAuthenticator{}
		mgr := New(
			WithDataBrokerClient(client),
			WithGetAuthenticator(func(_ context.Context, _ string) (identity.Authenticator, error) {
				return authenticator, nil
			}),
		)

		sess := validSession()
		sess.ExpiresAt = timestamppb.New(time.Now().Add(-1 * time.Hour))

		expectSessionDelete(client, sess)
		mgr.onUpdateSession(t.Context(), sess)
		mgr.refreshSession(t.Context(), "session-1")
	})
	t.Run("refresh disabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		authenticator := &mockAuthenticator{}
		mgr := New(
			WithDataBrokerClient(client),
			WithGetAuthenticator(func(_ context.Context, _ string) (identity.Authenticator, error) {
				return authenticator, nil
			}),
		)

		sess := validSession()
		sess.RefreshDisabled = true

		mgr.onUpdateSession(t.Context(), sess)
		mgr.refreshSession(t.Context(), "session-1")
		// no databroker calls expected
	})
	t.Run("missing token", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		authenticator := &mockAuthenticator{}
		mgr := New(
			WithDataBrokerClient(client),
			WithGetAuthenticator(func(_ context.Context, _ string) (identity.Authenticator, error) {
				return authenticator, nil
			}),
		)

		sess := validSession()
		sess.OauthToken = nil

		mgr.onUpdateSession(t.Context(), sess)
		mgr.refreshSession(t.Context(), "session-1")
		// no databroker calls expected
	})
	t.Run("refresh temporary error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		authenticator := &mockAuthenticator{
			refreshError: context.DeadlineExceeded,
		}
		mgr := New(
			WithDataBrokerClient(client),
			WithGetAuthenticator(func(_ context.Context, _ string) (identity.Authenticator, error) {
				return authenticator, nil
			}),
		)

		sess := validSession()

		mgr.onUpdateSession(t.Context(), sess)
		mgr.refreshSession(t.Context(), "session-1")
		// no databroker calls expected
	})
	t.Run("refresh fatal error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		authenticator := &mockAuthenticator{
			refreshError: errors.New("failed to refresh"),
		}
		mgr := New(
			WithDataBrokerClient(client),
			WithGetAuthenticator(func(_ context.Context, _ string) (identity.Authenticator, error) {
				return authenticator, nil
			}),
		)

		sess := validSession()
		expectSessionDelete(client, sess)

		mgr.onUpdateSession(t.Context(), sess)
		mgr.refreshSession(t.Context(), "session-1")
	})
	t.Run("user info temporary error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		authenticator := &mockAuthenticator{
			refreshResult: &oauth2.Token{
				AccessToken:  "new-access-token",
				RefreshToken: "new-refresh-token",
				Expiry:       time.Now().Add(1 * time.Hour),
			},
			updateUserInfoError: context.DeadlineExceeded,
		}
		mgr := New(
			WithDataBrokerClient(client),
			WithGetAuthenticator(func(_ context.Context, _ string) (identity.Authenticator, error) {
				return authenticator, nil
			}),
		)

		sess := validSession()

		mgr.onUpdateSession(t.Context(), sess)
		mgr.refreshSession(t.Context(), "session-1")
		// no databroker calls expected
	})
	t.Run("user info fatal error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		authenticator := &mockAuthenticator{
			refreshResult: &oauth2.Token{
				AccessToken:  "new-access-token",
				RefreshToken: "new-refresh-token",
				Expiry:       time.Now().Add(1 * time.Hour),
			},
			updateUserInfoError: errors.New("failed to get user info"),
		}
		mgr := New(
			WithDataBrokerClient(client),
			WithGetAuthenticator(func(_ context.Context, _ string) (identity.Authenticator, error) {
				return authenticator, nil
			}),
		)

		sess := validSession()
		expectSessionDelete(client, sess)

		mgr.onUpdateSession(t.Context(), sess)
		mgr.refreshSession(t.Context(), "session-1")
	})
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		newToken := &oauth2.Token{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			Expiry:       time.Now().Add(1 * time.Hour),
		}
		authenticator := &mockAuthenticator{
			refreshResult: newToken,
		}
		mgr := New(
			WithDataBrokerClient(client),
			WithGetAuthenticator(func(_ context.Context, _ string) (identity.Authenticator, error) {
				return authenticator, nil
			}),
		)

		sess := validSession()
		updated := proto.Clone(sess).(*session.Session)
		updated.OauthToken = &session.OAuthToken{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			ExpiresAt:    timestamppb.New(newToken.Expiry),
		}
		client.EXPECT().Patch(gomock.Any(), matchers.ProtoEq(&databroker.PatchRequest{
			Records: []*databroker.Record{{
				Type: "type.googleapis.com/session.Session",
				Id:   updated.Id,
				Data: protoutil.NewAny(updated),
			}},
			FieldMask: &fieldmaskpb.FieldMask{
				Paths: []string{"oauth_token", "id_token", "claims"},
			},
		})).Return(&databroker.PatchResponse{}, nil)
		u := &user.User{
			Id: "user-1",
		}
		client.EXPECT().Put(gomock.Any(), matchers.ProtoEq(&databroker.PutRequest{
			Records: []*databroker.Record{{
				Type: "type.googleapis.com/user.User",
				Id:   "user-1",
				Data: protoutil.NewAny(u),
			}},
		}))

		mgr.onUpdateUser(t.Context(), u)
		mgr.onUpdateSession(t.Context(), sess)
		mgr.refreshSession(t.Context(), "session-1")
	})
}

func expectSessionDelete(client *mock_databroker.MockDataBrokerServiceClient, s *session.Session) {
	record := &databroker.Record{
		Type: "type.googleapis.com/session.Session",
		Id:   s.Id,
		Data: protoutil.NewAny(s),
	}
	client.EXPECT().Get(gomock.Any(), matchers.ProtoEq(&databroker.GetRequest{
		Type: "type.googleapis.com/session.Session",
		Id:   s.Id,
	})).Return(&databroker.GetResponse{Record: record}, nil)
	client.EXPECT().Put(gomock.Any(), mock_databroker.DeleteRequestFor(record))
}
