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
	Validate() error
}

func getDataBrokerRecord(
	ctx context.Context,
	recordType string,
	recordID string,
	invalidate func(*databroker.Record) bool,
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

	// Check to see if we should invalidate the cache.
	if invalidate == nil || !invalidate(res.GetRecords()[0]) {
		return res.GetRecords()[0], nil
	}

	// retry with an up to date cache
	q.InvalidateCache(ctx, req)
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

	invalidate := func(record *databroker.Record) bool {
		// if the current record version is less than the lowest we'll accept, invalidate the cache
		if record.GetVersion() < dataBrokerRecordVersion {
			return true
		}

		// or if the session or service account is invalid, invalidate the cache
		_, err := validateSessionOrServiceAccount(record)
		return err != nil
	}

	record, err := getDataBrokerRecord(
		ctx, grpcutil.GetTypeURL(new(session.Session)), sessionID, invalidate)
	if storage.IsNotFound(err) {
		record, err = getDataBrokerRecord(ctx, grpcutil.GetTypeURL(new(user.ServiceAccount)), sessionID, invalidate)
	}
	if err != nil {
		return nil, err
	}

	s, err = validateSessionOrServiceAccount(record)
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

func validateSessionOrServiceAccount(record *databroker.Record) (sessionOrServiceAccount, error) {
	msg, err := record.GetData().UnmarshalNew()
	if err != nil {
		return nil, err
	}
	s := msg.(sessionOrServiceAccount)
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (a *Authorize) getDataBrokerUser(
	ctx context.Context,
	userID string,
) (*user.User, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.getDataBrokerUser")
	defer span.End()

	record, err := getDataBrokerRecord(ctx, grpcutil.GetTypeURL(new(user.User)), userID, nil)
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
