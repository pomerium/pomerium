// Package user contains protobuf types for users.
package user

import (
	context "context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// Get gets a user from the databroker.
func Get(ctx context.Context, client databroker.DataBrokerServiceClient, userID string) (*User, error) {
	any := protoutil.NewAny(new(User))

	res, err := client.Get(ctx, &databroker.GetRequest{
		Type: any.GetTypeUrl(),
		Id:   userID,
	})
	if err != nil {
		return nil, err
	}

	var u User
	err = res.GetRecord().GetData().UnmarshalTo(&u)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling user from databroker: %w", err)
	}

	return &u, nil
}

// Put sets a user in the databroker.
func Put(ctx context.Context, client databroker.DataBrokerServiceClient, u *User) (*databroker.Record, error) {
	any := protoutil.NewAny(u)
	res, err := client.Put(ctx, &databroker.PutRequest{
		Record: &databroker.Record{
			Type: any.GetTypeUrl(),
			Id:   u.Id,
			Data: any,
		},
	})
	if status.Code(err) == codes.ResourceExhausted {
		log.Warn(ctx).Msg("user: saving user resulted in resource exhausted error")
	}
	if err != nil {
		return nil, err
	}
	return res.GetRecord(), nil
}

// PutServiceAccount sets a service account in the databroker.
func PutServiceAccount(ctx context.Context, client databroker.DataBrokerServiceClient, sa *ServiceAccount) (*databroker.Record, error) {
	any := protoutil.NewAny(sa)
	res, err := client.Put(ctx, &databroker.PutRequest{
		Record: &databroker.Record{
			Type: any.GetTypeUrl(),
			Id:   sa.GetId(),
			Data: any,
		},
	})
	if status.Code(err) == codes.ResourceExhausted {
		log.Warn(ctx).Msg("user: saving service account resulted in resource exhausted error")
	}
	if err != nil {
		return nil, err
	}
	return res.GetRecord(), nil
}

// AddClaims adds the flattened claims to the user.
func (x *User) AddClaims(claims identity.FlattenedClaims) {
	if x.Claims == nil {
		x.Claims = make(map[string]*structpb.ListValue)
	}
	for k, svs := range claims.ToPB() {
		x.Claims[k] = svs
	}
}

// GetClaim returns a claim.
//
// This method is used by the dashboard template HTML to display claim data.
func (x *User) GetClaim(claim string) []interface{} {
	var vs []interface{}
	for _, sv := range x.GetClaims()[claim].GetValues() {
		vs = append(vs, sv.AsInterface())
	}
	return vs
}
