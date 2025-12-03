// Package session contains protobuf types for sessions.
package session

import (
	"bytes"
	context "context"
	"fmt"
	stdslices "slices"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/identity"
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

// Patch updates specific fields of an existing session in the databroker.
func Patch(
	ctx context.Context, client databroker.DataBrokerServiceClient,
	s *Session, fields *fieldmaskpb.FieldMask,
) (*databroker.PatchResponse, error) {
	s = proto.Clone(s).(*Session)
	data := protoutil.NewAny(s)
	res, err := client.Patch(ctx, &databroker.PatchRequest{
		Records: []*databroker.Record{{
			Type: data.GetTypeUrl(),
			Id:   s.Id,
			Data: data,
		}},
		FieldMask: fields,
	})
	return res, err
}

// New creates a new Session.
func New(idpID, id string) *Session {
	return &Session{
		IdpId: idpID,
		Id:    id,
	}
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
	x.IdToken, _ = ParseIDToken(rawIDToken)
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
	} {
		if expiresAt.AsTime().Year() > 1970 && now.After(expiresAt.AsTime()) {
			return fmt.Errorf("%w: %s expired at %s", ErrSessionExpired, name, expiresAt.AsTime())
		}
	}

	return nil
}

// ParseIDToken converts a raw ID token into an IDToken proto message.
// Does not perform any verification of the ID token.
func ParseIDToken(idToken string) (*IDToken, error) {
	if idToken == "" {
		return nil, nil
	}

	token, err := jwt.ParseSigned(idToken)
	if err != nil {
		return nil, err
	}
	var claims jwt.Claims
	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, err
	}
	return &IDToken{
		Raw:       idToken,
		Issuer:    claims.Issuer,
		Subject:   claims.Subject,
		ExpiresAt: timestamppb.New(claims.Expiry.Time()),
		IssuedAt:  timestamppb.New(claims.IssuedAt.Time()),
	}, nil
}

func (session *Session) Format() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "User ID:    %s\n", session.UserId)
	fmt.Fprintf(&b, "Session ID: %s\n", session.Id)
	fmt.Fprintf(&b, "Expires at: %s (in %s)\n",
		session.ExpiresAt.AsTime().String(),
		time.Until(session.ExpiresAt.AsTime()).Round(time.Second))
	fmt.Fprintf(&b, "Claims:\n")
	keys := make([]string, 0, len(session.Claims))
	for key := range session.Claims {
		keys = append(keys, key)
	}
	stdslices.Sort(keys)
	for _, key := range keys {
		fmt.Fprintf(&b, "  %s: ", key)
		vs := session.Claims[key].AsSlice()
		if len(vs) != 1 {
			b.WriteRune('[')
		}
		if len(vs) == 1 {
			switch key {
			case "iat":
				d, _ := vs[0].(float64)
				t := time.Unix(int64(d), 0)
				fmt.Fprintf(&b, "%s (%s ago)", t, time.Since(t).Round(time.Second))
			case "exp":
				d, _ := vs[0].(float64)
				t := time.Unix(int64(d), 0)
				fmt.Fprintf(&b, "%s (in %s)", t, time.Until(t).Round(time.Second))
			default:
				fmt.Fprintf(&b, "%#v", vs[0])
			}
		} else if len(vs) > 1 {
			for i, v := range vs {
				fmt.Fprintf(&b, "%#v", v)
				if i < len(vs)-1 {
					b.WriteString(", ")
				}
			}
		}
		if len(vs) != 1 {
			b.WriteRune(']')
		}
		b.WriteRune('\n')
	}
	return b.Bytes()
}
