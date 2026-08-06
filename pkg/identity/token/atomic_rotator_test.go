package token

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/databroker"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type mockAuthenticator struct {
	identity.Authenticator

	refreshResult       *oauth2.Token
	refreshError        error
	updateUserInfoError error
}

func (mock *mockAuthenticator) Refresh(_ context.Context, _ *oauth2.Token, _ identity.State) (*oauth2.Token, error) {
	return mock.refreshResult, mock.refreshError
}

func (mock *mockAuthenticator) UpdateUserInfo(_ context.Context, _ *oauth2.Token, _ any) error {
	return mock.updateUserInfoError
}

func TestRotateTokenSingle(t *testing.T) {
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

	newRotator := func(t *testing.T, authenticator identity.Authenticator) (*AtomicTokenRotator, databrokerpb.DataBrokerServiceClient) {
		t.Helper()
		client := newTestDataBrokerClient(t)
		return NewAtomicTokenRotator(NewStaticAuthenticatorGetter(authenticator), databrokerpb.NewStaticClientGetter(client)), client
	}

	// not ported: the rotator is handed a session by the caller, it never looks one up by id.
	// not ported ("no authenticator"): the authenticator is a constructor dependency, there is no
	// per-session authenticator lookup that can fail.

	t.Run("session expired", func(t *testing.T) {
		r, _ := newRotator(t, &mockAuthenticator{})

		sess := validSession()
		sess.ExpiresAt = timestamppb.New(time.Now().Add(-1 * time.Hour))

		res, err := r.RotateSessionToken(t.Context(), sess, nil)
		assert.Nil(t, res)
		assert.ErrorIs(t, err, ErrExpiredSession)
	})
	t.Run("refresh disabled", func(t *testing.T) {
		r, _ := newRotator(t, &mockAuthenticator{})

		sess := validSession()
		sess.RefreshDisabled = true

		res, err := r.RotateSessionToken(t.Context(), sess, nil)
		assert.Nil(t, res)
		assert.ErrorIs(t, err, ErrDoNotRefresh)
	})
	t.Run("missing token", func(t *testing.T) {
		r, _ := newRotator(t, &mockAuthenticator{})

		sess := validSession()
		sess.OauthToken = nil

		res, err := r.RotateSessionToken(t.Context(), sess, nil)
		assert.Nil(t, res)
		assert.ErrorIs(t, err, ErrDoNotRefresh)
	})
	t.Run("refresh temporary error", func(t *testing.T) {
		// TODO: the rotator does not yet distinguish temporary from fatal refresh errors,
		// see the TODO in runRotateLeased and the unused isTemporaryError.
	})
	t.Run("refresh fatal error", func(t *testing.T) {
		refreshError := errors.New("failed to refresh")
		r, _ := newRotator(t, &mockAuthenticator{refreshError: refreshError})

		sess := validSession()

		res, err := r.RotateSessionToken(t.Context(), sess, nil)
		assert.Nil(t, res)
		// the rotator only surfaces the error, deleting the session is the caller's decision.
		assert.ErrorIs(t, err, refreshError)
	})
	t.Run("user info temporary error", func(t *testing.T) {
		// TODO: the rotator does not yet distinguish temporary from fatal user info errors.
	})
	t.Run("user info fatal error", func(t *testing.T) {
		updateUserInfoError := errors.New("failed to get user info")
		r, _ := newRotator(t, &mockAuthenticator{
			refreshResult: &oauth2.Token{
				AccessToken:  "new-access-token",
				RefreshToken: "new-refresh-token",
				Expiry:       time.Now().Add(1 * time.Hour),
			},
			updateUserInfoError: updateUserInfoError,
		})

		sess := validSession()

		res, err := r.RotateSessionToken(t.Context(), sess, nil)
		assert.Nil(t, res)
		assert.ErrorIs(t, err, updateUserInfoError)
	})
	t.Run("ok", func(t *testing.T) {
		newToken := &oauth2.Token{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			Expiry:       time.Now().Add(1 * time.Hour),
		}
		r, client := newRotator(t, &mockAuthenticator{refreshResult: newToken})

		sess := validSession()
		u := &user.User{Id: "user-1"}
		_, err := databrokerpb.Put(t.Context(), client, sess)
		require.NoError(t, err)
		_, err = databrokerpb.Put(t.Context(), client, u)
		require.NoError(t, err)

		res, err := r.RotateSessionToken(t.Context(), sess, u)
		require.NoError(t, err)
		assert.Equal(t, newToken, res.Token)
		assert.Equal(t, u, res.User)
		testutil.AssertProtoEqual(t, &session.OAuthToken{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			ExpiresAt:    timestamppb.New(newToken.Expiry),
		}, res.Session.GetOauthToken())

		stored, err := session.Get(t.Context(), client, sess.GetId())
		require.NoError(t, err)
		testutil.AssertProtoEqual(t, res.Session.GetOauthToken(), stored.GetOauthToken())
	})
}

func TestRotateTokenConcurrent(t *testing.T) {
	t.Run("client waits until existing token is refreshed", func(t *testing.T) {
		newToken := &oauth2.Token{
			AccessToken:  "new-access-token",
			RefreshToken: "new-refresh-token",
			Expiry:       time.Now().Add(1 * time.Hour),
		}
		authenticator := &blockingAuthenticator{
			mockAuthenticator: mockAuthenticator{refreshResult: newToken},
			started:           make(chan struct{}),
			release:           make(chan struct{}),
		}

		client := newTestDataBrokerClient(t)
		r := NewAtomicTokenRotator(NewStaticAuthenticatorGetter(authenticator), databrokerpb.NewStaticClientGetter(client))

		iat := time.Now()
		sess := &session.Session{
			Id:        "session-1",
			UserId:    "user-1",
			IssuedAt:  timestamppb.New(iat),
			ExpiresAt: timestamppb.New(iat.Add(24 * time.Hour)),
			OauthToken: &session.OAuthToken{
				AccessToken:  "fake-access-token",
				RefreshToken: "fake-refresh-token",
			},
		}
		_, err := databrokerpb.Put(t.Context(), client, sess)
		require.NoError(t, err)

		type result struct {
			res *RotateTokenSuccess
			err error
		}
		rotate := func() <-chan result {
			done := make(chan result, 1)
			go func() {
				res, err := r.RotateSessionToken(t.Context(), proto.Clone(sess).(*session.Session), nil)
				done <- result{res: res, err: err}
			}()
			return done
		}

		// the first caller acquires the lease and blocks inside Refresh
		leader := rotate()
		select {
		case <-authenticator.started:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for the first refresh to start")
		}

		// the second caller finds the lease already held, so it must wait rather than
		// refresh a second time or return the stale token
		waiter := rotate()
		select {
		case got := <-waiter:
			t.Fatalf("second caller returned while the refresh was still in flight: %+v", got)
		case <-time.After(time.Second):
		}

		close(authenticator.release)

		leaderResult := <-leader
		require.NoError(t, leaderResult.err)
		assert.Equal(t, newToken, leaderResult.res.Token)

		waiterResult := <-waiter
		require.NoError(t, waiterResult.err)
		assert.Equal(t, newToken.AccessToken, waiterResult.res.Token.AccessToken)
		assert.Equal(t, newToken.RefreshToken, waiterResult.res.Token.RefreshToken)
		assert.Equal(t, int32(1), authenticator.refreshCount.Load())
	})

	t.Run("failed leased rotation", func(t *testing.T) {
		refreshError := errors.New("failed to refresh")
		authenticator := &blockingAuthenticator{
			mockAuthenticator: mockAuthenticator{refreshError: refreshError},
			started:           make(chan struct{}),
			release:           make(chan struct{}),
		}

		client := newTestDataBrokerClient(t)
		r := NewAtomicTokenRotator(NewStaticAuthenticatorGetter(authenticator), databrokerpb.NewStaticClientGetter(client))

		iat := time.Now()
		sess := &session.Session{
			Id:        "session-1",
			UserId:    "user-1",
			IssuedAt:  timestamppb.New(iat),
			ExpiresAt: timestamppb.New(iat.Add(24 * time.Hour)),
			OauthToken: &session.OAuthToken{
				AccessToken:  "fake-access-token",
				RefreshToken: "fake-refresh-token",
			},
		}
		_, err := databrokerpb.Put(t.Context(), client, sess)
		require.NoError(t, err)

		type result struct {
			res *RotateTokenSuccess
			err error
		}
		rotate := func(ctx context.Context) <-chan result {
			done := make(chan result, 1)
			go func() {
				res, err := r.RotateSessionToken(ctx, proto.Clone(sess).(*session.Session), nil)
				done <- result{res: res, err: err}
			}()
			return done
		}

		// the first caller acquires the lease and blocks inside Refresh
		leader := rotate(t.Context())
		select {
		case <-authenticator.started:
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for the first refresh to start")
		}

		// the lease holder's refresh fails, so the session is never rotated and the
		// waiting caller gives up once its own context expires
		waiterCtx, waiterCancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer waiterCancel()
		waiter := rotate(waiterCtx)

		close(authenticator.release)

		leaderResult := <-leader
		assert.Nil(t, leaderResult.res)
		assert.ErrorIs(t, leaderResult.err, refreshError)

		waiterResult := <-waiter
		assert.Nil(t, waiterResult.res)
		assert.ErrorIs(t, waiterResult.err, ErrTokenNotRotated)

		// the waiter never refreshes on its own, even after the lease holder fails
		assert.Equal(t, int32(1), authenticator.refreshCount.Load())

		stored, err := session.Get(t.Context(), client, sess.GetId())
		require.NoError(t, err)
		testutil.AssertProtoEqual(t, sess.GetOauthToken(), stored.GetOauthToken())
	})
}

type blockingAuthenticator struct {
	mockAuthenticator

	started      chan struct{}
	release      chan struct{}
	refreshCount atomic.Int32
}

func (mock *blockingAuthenticator) Refresh(ctx context.Context, t *oauth2.Token, s identity.State) (*oauth2.Token, error) {
	mock.refreshCount.Add(1)
	close(mock.started)
	select {
	case <-mock.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return mock.mockAuthenticator.Refresh(ctx, t, s)
}

func newTestDataBrokerClient(t *testing.T) databrokerpb.DataBrokerServiceClient {
	t.Helper()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)

	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, srv)
	})

	return databrokerpb.NewDataBrokerServiceClient(cc)
}
