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
	client databroker.DataBrokerServiceClient
}

var _ Reader = (*reader)(nil)

func NewReader(client databroker.DataBrokerServiceClient) Reader {
	return &reader{
		client: client,
	}
}

func (r *reader) GetBindingRequest(ctx context.Context, id CodeID) (*session.SessionBindingRequest, bool) {
	b := backoff.WithContext(backoff.NewExponentialBackOff(), ctx)
	resp, err := backoff.RetryWithData(func() (*databroker.GetResponse, error) {
		resp, err := r.client.Get(ctx, &databroker.GetRequest{
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

func (r *reader) GetSessionByUserID(ctx context.Context, userID string) (map[string]*IdentitySessionPair, error) {
	ret := map[string]*IdentitySessionPair{}
	filterByUser := indexedFieldFilter("user_id", userID)

	sessBindingRecs, err := r.client.Query(ctx, &databroker.QueryRequest{
		Type:   "type.googleapis.com/session.SessionBinding",
		Filter: filterByUser,
		Limit:  queryLimit,
	})

	if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
		return ret, nil
	}
	if err != nil {
		return nil, err
	}

	identityBindingRecs, err := r.client.Query(ctx, &databroker.QueryRequest{
		Type:   "type.googleapis.com/session.IdentityBinding",
		Filter: filterByUser,
		Limit:  queryLimit,
	})
	if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
		identityBindingRecs = &databroker.QueryResponse{
			Records: []*databroker.Record{},
		}
	} else if err != nil {
		return nil, err
	}

	for _, sb := range sessBindingRecs.GetRecords() {
		var sess session.SessionBinding
		if err := sb.GetData().UnmarshalTo(&sess); err != nil {
			log.Err(err).Ctx(ctx).Msg("GetSessionByUserID: failed to unmarshal session binding")
			continue
		}
		sessionID := sb.GetId()
		ret[sessionID] = &IdentitySessionPair{
			SB: &sess,
		}
	}

	for _, ib := range identityBindingRecs.GetRecords() {
		var ident session.IdentityBinding
		if err := ib.GetData().UnmarshalTo(&ident); err != nil {
			log.Err(err).Ctx(ctx).Msg("GetSessionByUserID: failed to unmarshal identity binding")
			continue
		}
		sessionID := ib.GetId()
		val, ok := ret[sessionID]
		if !ok {
			val = &IdentitySessionPair{}
		}
		val.IB = &ident
	}
	return ret, nil
}
