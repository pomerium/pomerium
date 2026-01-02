package code

import (
	"context"

	"github.com/cenkalti/backoff/v4"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

type revoker struct {
	clientB databroker.ClientGetter
}

var _ Revoker = (*revoker)(nil)

func NewRevoker(client databroker.ClientGetter) Revoker {
	return &revoker{
		clientB: client,
	}
}

func (r *revoker) RevokeCode(ctx context.Context, codeID CodeID) error {
	_, err := storage.DeleteDataBrokerRecord(ctx, r.clientB.GetDataBrokerServiceClient(), "type.googleapis.com/session.SessionBindingRequest", string(codeID))
	return err
}

func (r *revoker) RevokeIdentityBinding(ctx context.Context, bindingID BindingID) error {
	_, err := storage.DeleteDataBrokerRecord(ctx, r.clientB.GetDataBrokerServiceClient(), "type.googleapis.com/session.IdentityBinding", string(bindingID))
	return err
}

func (r *revoker) RevokeSessionBinding(ctx context.Context, bindingID BindingID) error {
	_, err := storage.DeleteDataBrokerRecord(ctx, r.clientB.GetDataBrokerServiceClient(), "type.googleapis.com/session.SessionBinding", string(bindingID))
	return err
}

func (r *revoker) RevokeSessionBindingBySession(ctx context.Context, sessionID string) ([]*databroker.Record, error) {
	b := backoff.WithContext(backoff.NewExponentialBackOff(), ctx)
	recs, err := backoff.RetryWithData(func() ([]*databroker.Record, error) {
		return getSessionBindingBySession(ctx, r.clientB.GetDataBrokerServiceClient(), sessionID)
	}, b)
	if err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return []*databroker.Record{}, nil
	}
	for _, rec := range recs {
		rec.DeletedAt = timestamppb.Now()
	}
	_, err = r.clientB.GetDataBrokerServiceClient().Patch(ctx, &databroker.PatchRequest{
		Records: recs,
	})
	return recs, err
}
