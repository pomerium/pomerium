package code

import (
	"context"

	"github.com/cenkalti/backoff/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
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
	rec, err := r.clientB.GetDataBrokerServiceClient().
		Get(ctx, &databroker.GetRequest{
			Type: "type.googleapis.com/session.SessionBindingRequest",
			Id:   string(codeID),
		})

	if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
		return nil
	} else if err != nil {
		return err
	}

	if rec.GetRecord().GetDeletedAt() != nil {
		return nil
	}

	rec.Record.DeletedAt = timestamppb.Now()

	_, err = r.clientB.GetDataBrokerServiceClient().
		Patch(ctx, &databroker.PatchRequest{
			Records: []*databroker.Record{
				rec.Record,
			},
		})
	return err
}

func (r *revoker) RevokeIdentityBinding(ctx context.Context, bindingID BindingID) error {
	ibResp, err := r.clientB.GetDataBrokerServiceClient().
		Get(ctx, &databroker.GetRequest{
			Type: "type.googleapis.com/session.IdentityBinding",
			Id:   string(bindingID),
		})

	if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
		return nil
	}

	if ibResp.GetRecord().GetDeletedAt() != nil {
		return nil
	}

	rec := ibResp.Record
	rec.DeletedAt = timestamppb.Now()
	_, err = r.clientB.GetDataBrokerServiceClient().Put(
		ctx,
		&databroker.PutRequest{
			Records: []*databroker.Record{
				rec,
			},
		},
	)
	return err
}

func (r *revoker) RevokeSessionBinding(ctx context.Context, bindingID BindingID) error {
	sbResp, err := r.clientB.GetDataBrokerServiceClient().
		Get(ctx, &databroker.GetRequest{
			Type: "type.googleapis.com/session.SessionBinding",
			Id:   string(bindingID),
		})

	if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if sbResp.Record.GetDeletedAt() != nil {
		return nil
	}
	rec := sbResp.Record
	rec.DeletedAt = timestamppb.Now()
	_, err = r.clientB.GetDataBrokerServiceClient().
		Patch(ctx, &databroker.PatchRequest{
			Records: []*databroker.Record{
				rec,
			},
		})
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
