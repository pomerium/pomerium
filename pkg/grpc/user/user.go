// Package user contains protobuf types for users.
package user

import (
	context "context"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// Get gets a user from the databroker.
func Get(ctx context.Context, client databroker.DataBrokerServiceClient, userID string) (*User, error) {
	u := &User{Id: userID}
	return u, databroker.Get(ctx, client, u)
}

// GetServiceAccount gets a service account from the databroker.
func GetServiceAccount(ctx context.Context, client databroker.DataBrokerServiceClient, serviceAccountID string) (*ServiceAccount, error) {
	sa := &ServiceAccount{Id: serviceAccountID}
	return sa, databroker.Get(ctx, client, sa)
}

// PutServiceAccount saves a service account to the databroker.
func PutServiceAccount(ctx context.Context, client databroker.DataBrokerServiceClient, serviceAccount *ServiceAccount) (*databroker.PutResponse, error) {
	return databroker.Put(ctx, client, serviceAccount)
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
