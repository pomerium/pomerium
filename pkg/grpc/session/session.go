// Package session contains protobuf types for sessions.
package session

import (
	context "context"

	"github.com/golang/protobuf/ptypes"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

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
