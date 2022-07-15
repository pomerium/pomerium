package authorize

import (
	"context"

	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

type sessionOrServiceAccount interface {
	GetUserId() string
}

func getDataBrokerRecord(
	ctx context.Context,
	recordType string,
	recordID string,
	lowestRecordVersion uint64,
) (*databroker.Record, error) {
	q := storage.GetQuerier(ctx)

	req := &databroker.QueryRequest{
		Type:  recordType,
		Limit: 1,
	}
	req.SetFilterByIDOrIndex(recordID)

	res, err := q.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(res.GetRecords()) == 0 {
		return nil, storage.ErrNotFound
	}

	// if the current record version is less than the lowest we'll accept, invalidate the cache
	if res.GetRecords()[0].GetVersion() < lowestRecordVersion {
		q.InvalidateCache(ctx, req)
	} else {
		return res.GetRecords()[0], nil
	}

	// retry with an up to date cache
	res, err = q.Query(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(res.GetRecords()) == 0 {
		return nil, storage.ErrNotFound
	}

	return res.GetRecords()[0], nil
}

func (a *Authorize) getDataBrokerSessionOrServiceAccount(
	ctx context.Context,
	sessionID string,
	dataBrokerRecordVersion uint64,
) (s sessionOrServiceAccount, err error) {
	ctx, span := trace.StartSpan(ctx, "authorize.getDataBrokerSessionOrServiceAccount")
	defer span.End()

	record, err := getDataBrokerRecord(ctx, grpcutil.GetTypeURL(new(session.Session)), sessionID, dataBrokerRecordVersion)
	if storage.IsNotFound(err) {
		record, err = getDataBrokerRecord(ctx, grpcutil.GetTypeURL(new(user.ServiceAccount)), sessionID, dataBrokerRecordVersion)
	}
	if err != nil {
		return nil, err
	}

	msg, err := record.GetData().UnmarshalNew()
	if err != nil {
		return nil, err
	}
	s = msg.(sessionOrServiceAccount)

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
