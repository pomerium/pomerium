package authorize

import (
	"context"

	"github.com/open-policy-agent/opa/storage"

	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

type sessionOrServiceAccount interface {
	GetUserId() string
}

func (a *Authorize) getDataBrokerSessionOrServiceAccount(ctx context.Context, sessionID string) (s sessionOrServiceAccount, err error) {
	ctx, span := trace.StartSpan(ctx, "authorize.getDataBrokerSessionOrServiceAccount")
	defer span.End()

	client := a.state.Load().dataBrokerClient

	s, err = session.Get(ctx, client, sessionID)
	if storage.IsNotFound(err) {
		s, err = user.GetServiceAccount(ctx, client, sessionID)
	}
	if err != nil {
		return nil, err
	}

	if _, ok := s.(*session.Session); ok {
		a.accessTracker.TrackSessionAccess(sessionID)
	}
	if _, ok := s.(*user.ServiceAccount); ok {
		a.accessTracker.TrackServiceAccountAccess(sessionID)
	}
	return s, nil
}

func (a *Authorize) getDataBrokerUser(ctx context.Context, userID string) (u *user.User, err error) {
	ctx, span := trace.StartSpan(ctx, "authorize.getDataBrokerUser")
	defer span.End()

	client := a.state.Load().dataBrokerClient

	u, err = user.Get(ctx, client, userID)
	return u, err
}
