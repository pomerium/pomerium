package token

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/pomerium/pomerium/pkg/grpc/user"

	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
	metrics_ids "github.com/pomerium/pomerium/pkg/metrics"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	ErrStorageLease    = errors.New("storage error from lease")
	ErrExpiredSession  = errors.New("expired session")
	ErrDoNotRefresh    = errors.New("refresh disabled")
	ErrTokenNotRotated = errors.New("token not rotated")
)

type AuthenticatorGetter interface {
	GetAuthenticator() identity.Authenticator
}

func NewStaticAuthenticatorGetter(a identity.Authenticator) AuthenticatorGetter {
	return staticAuthenticatorGetter{a: a}
}

type staticAuthenticatorGetter struct {
	a identity.Authenticator
}

func (s staticAuthenticatorGetter) GetAuthenticator() identity.Authenticator {
	return s.a
}

type EventDispatcherGetter interface {
	GetEventDispatcher() *events.Manager
}

type TokenRotatorOptions struct {
	now        func() time.Time
	dispatcher EventDispatcherGetter
}

func (o *TokenRotatorOptions) Apply(opts ...TokenRotatorOption) {
	for _, opt := range opts {
		opt(o)
	}
}

type TokenRotatorOption func(o *TokenRotatorOptions)

func WithClock(now func() time.Time) TokenRotatorOption {
	return func(o *TokenRotatorOptions) {
		o.now = now
	}
}

func WithEventDispatcher(dispatcher EventDispatcherGetter) TokenRotatorOption {
	return func(o *TokenRotatorOptions) {
		o.dispatcher = dispatcher
	}
}

type AtomicTokenRotator struct {
	authenticator AuthenticatorGetter
	clientB       databroker.ClientGetter
	TokenRotatorOptions
}

func NewAtomicTokenRotator(
	authenticator AuthenticatorGetter,
	clientB databroker.ClientGetter,
	opts ...TokenRotatorOption,
) *AtomicTokenRotator {
	options := &TokenRotatorOptions{
		now: time.Now,
	}
	options.Apply(opts...)

	return &AtomicTokenRotator{
		authenticator:       authenticator,
		clientB:             clientB,
		TokenRotatorOptions: *options,
	}
}

type RotateTokenSuccess struct {
	Session *session.Session
	User    *user.User
	Token   *oauth2.Token
}

func (r *AtomicTokenRotator) RotateSessionToken(
	ctx context.Context,
	s *session.Session,
	u *user.User,
) (
	*RotateTokenSuccess,
	error,
) {
	expiry := s.GetExpiresAt().AsTime()
	if expiry.Before(r.now()) {
		return nil, ErrExpiredSession
	}

	if s.GetRefreshDisabled() {
		// refresh was explicitly disabled
		return nil, ErrDoNotRefresh
	}

	if s.GetOauthToken() == nil {
		return nil, ErrDoNotRefresh
	}
	authenticator := r.authenticator.GetAuthenticator()
	if authenticator == nil {
		return nil, ErrDoNotRefresh
	}

	leaseDur := 30 * time.Second
	_, err := r.clientB.GetDataBrokerServiceClient().
		AcquireLease(ctx, &databroker.AcquireLeaseRequest{
			Name:     s.GetId(),
			Duration: durationpb.New(leaseDur),
		})

	if err == nil {
		// intentionally do not rotate lease to prevent clients reading back
		// new sessions that may race against newly acquired leases
		return r.runRotateLeased(ctx, authenticator, s, u)
	}
	if status.Code(err) == codes.AlreadyExists {
		leaseCtx, leaseCa := context.WithTimeout(ctx, 30*time.Second)
		defer leaseCa()
		b := backoff.NewExponentialBackOff()
		s, err := backoff.RetryWithData(func() (*session.Session, error) {
			newSession, err := session.Get(ctx, r.clientB.GetDataBrokerServiceClient(), s.GetId())
			if err != nil {
				return nil, err
			}
			if newSession.GetOauthToken().GetRefreshToken() != s.GetOauthToken().GetRefreshToken() {
				return newSession, nil
			}
			return nil, ErrTokenNotRotated
		}, backoff.WithContext(b, leaseCtx))
		if err != nil {
			return nil, fmt.Errorf("%w : %w", ErrTokenNotRotated, err)
		}

		if u != nil {
			// get user
			newU, err := user.Get(ctx, r.clientB.GetDataBrokerServiceClient(), u.GetId())
			if err != nil {
				panic(err) // TODO:
			}
			u = newU
		}
		return &RotateTokenSuccess{
			Session: s,
			User:    u,
			Token:   FromOAuthToken(s.GetOauthToken()),
		}, nil
	}

	return nil, fmt.Errorf("%w : %w", ErrStorageLease, err)
}

func (r *AtomicTokenRotator) runRotateLeased(
	ctx context.Context,
	authenticator identity.Authenticator,
	s *session.Session,
	u *user.User,
) (*RotateTokenSuccess, error) {
	leaseCtx, leaseCa := context.WithTimeout(ctx, 30*time.Second)
	defer leaseCa()
	newToken, err := authenticator.Refresh(leaseCtx, FromOAuthToken(s.GetOauthToken()), NewSessionUnmarshaler(s))
	metrics.RecordIdentityManagerSessionRefresh(ctx, err)
	r.recordLastError(metrics_ids.IdentityManagerLastSessionRefreshError, err)
	if err != nil {
		return nil, err
	}

	s.OauthToken = ToOAuthToken(newToken)
	err = authenticator.UpdateUserInfo(ctx, FromOAuthToken(s.OauthToken), newMultiUnmarshaler(newUserUnmarshaler(u), NewSessionUnmarshaler(s)))
	metrics.RecordIdentityManagerUserRefresh(ctx, err)
	r.recordLastError(metrics_ids.IdentityManagerLastUserRefreshError, err)
	if err != nil {
		return nil, err
	}
	// TODO : renew lease in the background, while we update session, user info?
	if err := r.updateSession(ctx, s); err != nil {
		return nil, err
	}
	if u != nil {
		if err := r.updateUser(ctx, u); err != nil {
			return nil, err
		}
	}

	return &RotateTokenSuccess{
		Session: s,
		User:    u,
		Token:   newToken,
	}, nil
}

func (r *AtomicTokenRotator) recordLastError(id string, err error) {
	if err == nil || r.dispatcher == nil {
		return
	}
	evtMgr := r.dispatcher.GetEventDispatcher()
	if evtMgr == nil {
		return
	}
	evtMgr.Dispatch(&events.LastError{
		Time:    timestamppb.Now(),
		Message: err.Error(),
		Id:      id,
	})
}

func (r *AtomicTokenRotator) updateSession(ctx context.Context, s *session.Session) error {
	log.Ctx(ctx).Debug().
		Str("user-id", s.GetUserId()).
		Str("session-id", s.GetId()).
		Msg("updating session")

	fm, err := fieldmaskpb.New(s, "oauth_token", "id_token", "claims")
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("user-id", s.GetUserId()).
			Str("session-id", s.GetId()).
			Msg("failed to create fieldmask for session")
		return err
	}

	_, err = session.Patch(ctx, r.clientB.GetDataBrokerServiceClient(), s, fm)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).
			Str("user-id", s.GetUserId()).
			Str("session-id", s.GetId()).
			Msg("failed to patch updated session record")
		return err
	}
	return nil
}

func (r *AtomicTokenRotator) updateUser(ctx context.Context, u *user.User) error {
	_, err := databroker.Put(ctx, r.clientB.GetDataBrokerServiceClient(), u)
	if err != nil {
		log.Ctx(ctx).Error().
			Str("user-id", u.GetId()).
			Err(err).
			Msg("failed to store updated user record")
		return err
	}
	return nil
}

// TODO : duplicated
// FromOAuthToken converts a session oauth token to oauth2.Token.
func FromOAuthToken(token *session.OAuthToken) *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  token.GetAccessToken(),
		TokenType:    token.GetTokenType(),
		RefreshToken: token.GetRefreshToken(),
		Expiry:       token.GetExpiresAt().AsTime(),
	}
}

// TODO : duplicated
// ToOAuthToken converts an oauth2.Token to a session oauth token.
func ToOAuthToken(token *oauth2.Token) *session.OAuthToken {
	expiry := timestamppb.New(token.Expiry)
	return &session.OAuthToken{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    expiry,
	}
}
