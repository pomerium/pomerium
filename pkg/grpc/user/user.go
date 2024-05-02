// Package user contains protobuf types for users.
package user

import (
	context "context"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/slices"
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

// ErrServiceAccountExpired indicates the service account has expired.
var ErrServiceAccountExpired = fmt.Errorf("service account has expired")

// Validate returns an error if the service account is not valid.
func (x *ServiceAccount) Validate() error {
	now := time.Now()
	for _, expiresAt := range []*timestamppb.Timestamp{
		x.GetExpiresAt(),
	} {
		if expiresAt.AsTime().Year() > 1970 && now.After(expiresAt.AsTime()) {
			return ErrServiceAccountExpired
		}
	}

	return nil
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
func (x *User) GetClaim(claim string) []any {
	var vs []any
	for _, sv := range x.GetClaims()[claim].GetValues() {
		vs = append(vs, sv.AsInterface())
	}
	return vs
}

// AddDeviceCredentialID adds a device credential id to the list of device credential ids.
func (x *User) AddDeviceCredentialID(deviceCredentialID string) {
	x.DeviceCredentialIds = slices.Unique(append(x.DeviceCredentialIds, deviceCredentialID))
}

// HasDeviceCredentialID returns true if the user has the device credential id.
func (x *User) HasDeviceCredentialID(deviceCredentialID string) bool {
	return slices.Contains(x.DeviceCredentialIds, deviceCredentialID)
}

// RemoveDeviceCredentialID removes the device credential id from the list of device credential ids.
func (x *User) RemoveDeviceCredentialID(deviceCredentialID string) {
	x.DeviceCredentialIds = slices.Remove(x.DeviceCredentialIds, deviceCredentialID)
}
