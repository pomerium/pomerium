// Package session contains protobuf types for sessions.
package session

import (
	context "context"

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// Delete deletes a session from the databroker.
func Delete(ctx context.Context, client databroker.DataBrokerServiceClient, sessionID string) error {
	any, _ := ptypes.MarshalAny(new(Session))
	_, err := client.Delete(ctx, &databroker.DeleteRequest{
		Type: any.GetTypeUrl(),
		Id:   sessionID,
	})
	return err
}

// Get gets a session from the databroker.
func Get(ctx context.Context, client databroker.DataBrokerServiceClient, sessionID string) (*Session, error) {
	any, _ := ptypes.MarshalAny(new(Session))

	res, err := client.Get(ctx, &databroker.GetRequest{
		Type: any.GetTypeUrl(),
		Id:   sessionID,
	})
	if err != nil {
		return nil, err
	}

	var s Session
	err = ptypes.UnmarshalAny(res.GetRecord().GetData(), &s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// Set sets a session in the databroker.
func Set(ctx context.Context, client databroker.DataBrokerServiceClient, s *Session) (*databroker.SetResponse, error) {
	any, _ := anypb.New(s)
	res, err := client.Set(ctx, &databroker.SetRequest{
		Type: any.GetTypeUrl(),
		Id:   s.Id,
		Data: any,
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}
