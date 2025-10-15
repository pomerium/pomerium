package session

import (
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"google.golang.org/protobuf/proto"
)

// The handleJWT represents the data as it is stored in the JWT. This matches how
// Pomerium has stored data historically to support loading existing sessions.
type handleJWT struct {
	jwt.Claims
	IdentityProviderID      string `json:"idp_id,omitempty"`
	DataBrokerServerVersion uint64 `json:"databroker_server_version,omitempty"`
	DataBrokerRecordVersion uint64 `json:"databroker_record_version,omitempty"`
}

// MarshalAndSignHandle creates a signed JWT for the handle.
func MarshalAndSignHandle(key []byte, h *Handle) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       key,
	}, &jose.SignerOptions{})
	if err != nil {
		return "", fmt.Errorf("error creating session handle signer: %w", err)
	}

	str, err := jwt.Signed(signer).Claims(h.toJWT()).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("error marshaling jwt: %w", err)
	}

	return str, nil
}

// UnmarshalAndVerifyHandle converts a signed JWT into a handle and verifies its signature.
func UnmarshalAndVerifyHandle(key []byte, str string) (*Handle, error) {
	t, err := jwt.ParseSigned(str)
	if err != nil {
		return nil, err
	}

	var jwt handleJWT
	err = t.Claims(key, &jwt)
	if err != nil {
		return nil, err
	}

	h := new(Handle)
	h.fromJWT(jwt)
	return h, nil
}

// MarshalJSON marshals a handle as JSON.
func (x *Handle) MarshalJSON() ([]byte, error) {
	return json.Marshal(x.toJWT())
}

// UnmarshalJSON unmarshals a handle from JSON.
func (x *Handle) UnmarshalJSON(rawJSON []byte) error {
	var jwt handleJWT
	err := json.Unmarshal(rawJSON, &jwt)
	if err != nil {
		return err
	}
	x.fromJWT(jwt)
	return nil
}

func (x *Handle) fromJWT(jwt handleJWT) {
	x.Reset()
	x.Id = jwt.ID
	x.Audience = jwt.Audience
	if jwt.IdentityProviderID != "" {
		x.IdentityProviderId = proto.String(jwt.IdentityProviderID)
	}
	if jwt.Subject != "" {
		x.UserId = proto.String(jwt.Subject)
	}
	if jwt.DataBrokerServerVersion > 0 {
		x.DataBrokerServerVersion = proto.Uint64(jwt.DataBrokerServerVersion)
	}
	if jwt.DataBrokerRecordVersion > 0 {
		x.DataBrokerRecordVersion = proto.Uint64(jwt.DataBrokerRecordVersion)
	}
}

func (x *Handle) toJWT() handleJWT {
	return handleJWT{
		Claims: jwt.Claims{
			Subject:  x.GetUserId(),
			Audience: x.GetAudience(),
			ID:       x.GetId(),
		},
		IdentityProviderID:      x.GetIdentityProviderId(),
		DataBrokerServerVersion: x.GetDataBrokerServerVersion(),
		DataBrokerRecordVersion: x.GetDataBrokerRecordVersion(),
	}
}
