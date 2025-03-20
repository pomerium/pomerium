package authorize

import (
	"context"

	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

type sessionOrServiceAccount interface {
	GetId() string
	GetUserId() string
	Validate() error
}

func (a *Authorize) getDataBrokerSessionOrServiceAccount(
	ctx context.Context,
	sessionID string,
	dataBrokerRecordVersion uint64,
) (s sessionOrServiceAccount, err error) {
	ctx, span := a.tracer.Start(ctx, "authorize.getDataBrokerSessionOrServiceAccount")
	defer span.End()

	record, err := storage.GetDataBrokerRecord(ctx, grpcutil.GetTypeURL(new(session.Session)), sessionID, dataBrokerRecordVersion)
	if storage.IsNotFound(err) {
		record, err = storage.GetDataBrokerRecord(ctx, grpcutil.GetTypeURL(new(user.ServiceAccount)), sessionID, dataBrokerRecordVersion)
	}
	if err != nil {
		return nil, err
	}

	msg, err := record.GetData().UnmarshalNew()
	if err != nil {
		return nil, err
	}
	s = msg.(sessionOrServiceAccount)
	if err := s.Validate(); err != nil {
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

func (a *Authorize) getDataBrokerUser(
	ctx context.Context,
	userID string,
) (*user.User, error) {
	ctx, span := a.tracer.Start(ctx, "authorize.getDataBrokerUser")
	defer span.End()

	record, err := storage.GetDataBrokerRecord(ctx, grpcutil.GetTypeURL(new(user.User)), userID, 0)
	if err != nil {
		return nil, err
	}

	var u user.User
	err = record.GetData().UnmarshalTo(&u)
	if err != nil {
		return nil, err
	}
	return &u, nil
}
