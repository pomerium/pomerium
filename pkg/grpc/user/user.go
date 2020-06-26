// Package user contains protobuf types for users.
package user

import (
	context "context"

	"github.com/golang/protobuf/ptypes"

	"github.com/pomerium/pomerium/internal/protoutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// Get gets a user from the databroker.
func Get(ctx context.Context, client databroker.DataBrokerServiceClient, userID string) (*User, error) {
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

// GetClaim gets a claim.
func (user *User) GetClaim(claim string) interface{} {
	return protoutil.AnyToInterface(user.GetClaims()[claim])
}
