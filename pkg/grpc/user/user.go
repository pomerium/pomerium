// Package user contains protobuf types for users.
package user

import (
	context "context"
	"fmt"

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/protobuf/types/known/anypb"

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
		return nil, fmt.Errorf("error getting user from databroker: %w", err)
	}

	var u User
	err = ptypes.UnmarshalAny(res.GetRecord().GetData(), &u)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling user from databroker: %w", err)
	}
	return &u, nil
}

// GetClaim gets a claim.
func (user *User) GetClaim(claim string) interface{} {
	return protoutil.AnyToInterface(user.GetClaims()[claim])
}

// Set sets a user in the databroker.
func Set(ctx context.Context, client databroker.DataBrokerServiceClient, u *User) (*databroker.Record, error) {
	any, _ := anypb.New(u)
	res, err := client.Set(ctx, &databroker.SetRequest{
		Type: any.GetTypeUrl(),
		Id:   u.Id,
		Data: any,
	})
	if err != nil {
		return nil, fmt.Errorf("error setting user in databroker: %w", err)
	}
	return res.GetRecord(), nil
}

// SetServiceAccount sets a service account in the databroker.
func SetServiceAccount(ctx context.Context, client databroker.DataBrokerServiceClient, sa *ServiceAccount) (*databroker.Record, error) {
	any, _ := anypb.New(sa)
	res, err := client.Set(ctx, &databroker.SetRequest{
		Type: any.GetTypeUrl(),
		Id:   sa.GetId(),
		Data: any,
	})
	if err != nil {
		return nil, fmt.Errorf("error setting service account in databroker: %w", err)
	}
	return res.GetRecord(), nil
}
