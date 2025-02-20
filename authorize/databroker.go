package authorize

import (
	"context"

	octrace "go.opencensus.io/trace"

	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
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

func getDataBrokerRecord(
	ctx context.Context,
	recordType string,
	recordID string,
	lowestRecordVersion uint64,
) (*databroker.Record, error) {
	ctx, span := trace.StartSpan(ctx, "authorize.getDataBrokerRecord")
	span.AddAttributes(
		octrace.StringAttribute("record_type", recordType),
		octrace.StringAttribute("record_id", recordID),
		octrace.Int64Attribute("lowest_record_version", int64(lowestRecordVersion)),
	)
	defer span.End()

	q := storage.GetQuerier(ctx)

	req := &databroker.QueryRequest{
		Type:  recordType,
		Limit: 1,
	}
	req.SetFilterByIDOrIndex(recordID)

	res, err := q.Query(ctx, req)
	if err != nil {
		span.SetStatus(octrace.Status{Code: octrace.StatusCodeInternal, Message: err.Error()})
		return nil, err
	}
	if len(res.GetRecords()) == 0 {
		span.SetStatus(octrace.Status{Code: octrace.StatusCodeNotFound})
		return nil, storage.ErrNotFound
	}

	// if the current record version is less than the lowest we'll accept, invalidate the cache
	if v := res.GetRecords()[0].GetVersion(); v < lowestRecordVersion {
		span.AddAttributes(octrace.Int64Attribute("got_record_version", int64(v)))
		q.InvalidateCache(ctx, req)
	} else {
		return res.GetRecords()[0], nil
	}

	// retry with an up to date cache
	res, err = q.Query(ctx, req)
	if err != nil {
		span.SetStatus(octrace.Status{Code: octrace.StatusCodeInternal, Message: err.Error()})
		return nil, err
	}
	if len(res.GetRecords()) == 0 {
		span.SetStatus(octrace.Status{Code: octrace.StatusCodeNotFound})
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
	ctx, span := trace.StartSpan(ctx, "authorize.getDataBrokerUser")
	span.AddAttributes(octrace.StringAttribute("user_id", userID))
	defer span.End()

	record, err := getDataBrokerRecord(ctx, grpcutil.GetTypeURL(new(user.User)), userID, 0)
	if err != nil {
		span.SetStatus(octrace.Status{Code: octrace.StatusCodeInternal, Message: err.Error()})
		return nil, err
	}

	var u user.User
	err = record.GetData().UnmarshalTo(&u)
	if err != nil {
		return nil, err
	}
	return &u, nil
}
