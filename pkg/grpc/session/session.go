// Package session contains protobuf types for sessions.
package session

import (
	context "context"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/slices"
)

// Delete deletes a session from the databroker.
func Delete(ctx context.Context, client databroker.DataBrokerServiceClient, sessionID string) error {
	data := protoutil.NewAny(new(Session))
	_, err := client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Type:      data.GetTypeUrl(),
			Id:        sessionID,
			Data:      data,
			DeletedAt: timestamppb.Now(),
		}},
	})
	return err
}

// Get gets a session from the databroker.
func Get(ctx context.Context, client databroker.DataBrokerServiceClient, sessionID string) (*Session, error) {
	data := protoutil.NewAny(new(Session))
	res, err := client.Get(ctx, &databroker.GetRequest{
		Type: data.GetTypeUrl(),
		Id:   sessionID,
	})
	if err != nil {
		return nil, err
	}

	var s Session
	err = res.GetRecord().GetData().UnmarshalTo(&s)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling session from databroker: %w", err)
	}
	return &s, nil
}

// Put sets a session in the databroker.
func Put(ctx context.Context, client databroker.DataBrokerServiceClient, s *Session) (*databroker.PutResponse, error) {
	s = proto.Clone(s).(*Session)
	data := protoutil.NewAny(s)
	res, err := client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Type: data.GetTypeUrl(),
			Id:   s.Id,
			Data: data,
		}},
	})
	return res, err
}

// AddClaims adds the flattened claims to the session.
func (x *Session) AddClaims(claims identity.FlattenedClaims) {
	if x.Claims == nil {
		x.Claims = make(map[string]*structpb.ListValue)
	}
	for k, svs := range claims.ToPB() {
		x.Claims[k] = svs
	}
}

// SetRawIDToken sets the raw id token.
func (x *Session) SetRawIDToken(rawIDToken string) {
	if x.IdToken == nil {
		x.IdToken = new(IDToken)
	}
	x.IdToken.Raw = rawIDToken
}

// RemoveDeviceCredentialID removes a device credential id.
func (x *Session) RemoveDeviceCredentialID(deviceCredentialID string) {
	x.DeviceCredentials = slices.Filter(x.DeviceCredentials, func(el *Session_DeviceCredential) bool {
		return el.GetId() != deviceCredentialID
	})
}

// ErrSessionExpired indicates the session has expired
var ErrSessionExpired = fmt.Errorf("session has expired")

// Validate returns an error if the session is not valid.
func (x *Session) Validate() error {
	now := time.Now()
	for name, expiresAt := range map[string]*timestamppb.Timestamp{
		"session":      x.GetExpiresAt(),
		"access_token": x.GetOauthToken().GetExpiresAt(),
		"id_token":     x.GetIdToken().GetExpiresAt(),
	} {
		if expiresAt.AsTime().Year() > 1970 && now.After(expiresAt.AsTime()) {
			return fmt.Errorf("%w: %s expired at %s", ErrSessionExpired, name, expiresAt.AsTime())
		}
	}

	return nil
}
