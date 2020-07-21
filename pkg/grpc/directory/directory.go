// Package directory contains protobuf types for directory users.
package directory

import (
	context "context"

	"github.com/golang/protobuf/ptypes"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// GetGroup gets a directory group from the databroker.
func GetGroup(ctx context.Context, client databroker.DataBrokerServiceClient, groupID string) (*Group, error) {
	any, _ := ptypes.MarshalAny(new(Group))

	res, err := client.Get(ctx, &databroker.GetRequest{
		Type: any.GetTypeUrl(),
		Id:   groupID,
	})
	if err != nil {
		return nil, err
	}

	var g Group
	err = ptypes.UnmarshalAny(res.GetRecord().GetData(), &g)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// GetUser gets a directory user from the databroker.
func GetUser(ctx context.Context, client databroker.DataBrokerServiceClient, userID string) (*User, error) {
	any, _ := ptypes.MarshalAny(new(User))

	res, err := client.Get(ctx, &databroker.GetRequest{
		Type: any.GetTypeUrl(),
		Id:   userID,
	})
	if err != nil {
		return nil, err
	}

	var u User
	err = ptypes.UnmarshalAny(res.GetRecord().GetData(), &u)
	if err != nil {
		return nil, err
	}
	return &u, nil
}
