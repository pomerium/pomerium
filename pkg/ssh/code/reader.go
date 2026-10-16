package code

import (
	"context"

	"github.com/cenkalti/backoff/v4"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

type reader struct {
	clientB databroker.ClientGetter
}

var _ Reader = (*reader)(nil)

func NewReader(client databroker.ClientGetter) Reader {
	return &reader{
		clientB: client,
	}
}

func (r *reader) GetBindingRequest(ctx context.Context, id CodeID) (*session.SessionBindingRequest, bool) {
	b := backoff.WithContext(backoff.NewExponentialBackOff(), ctx)
	resp, err := backoff.RetryWithData(func() (*databroker.GetResponse, error) {
		resp, err := r.clientB.GetDataBrokerServiceClient().
			Get(ctx, &databroker.GetRequest{
				Type: "type.googleapis.com/session.SessionBindingRequest",
				Id:   string(id),
			})
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return nil, backoff.Permanent(err)
		}
		if err != nil {
			return nil, err
		}
		return resp, nil
	}, b)
	if err != nil {
		return nil, false
	}
	s := &session.SessionBindingRequest{}
	if err := resp.GetRecord().GetData().UnmarshalTo(s); err != nil {
		log.Err(err).Ctx(ctx).Msg("GetBindingRequest: failed to unmarshal session binding request")
		return nil, false
	}
	return s, true
}
