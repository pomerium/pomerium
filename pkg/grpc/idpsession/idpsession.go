package idpsession

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/pomerium/pomerium/pkg/mapsutil"
	structpb "google.golang.org/protobuf/types/known/structpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

// implements identity.State
func (x *IDPSession) SetRawIDToken(rawIDToken string) {
	if x == nil {
		return
	}
	x.RawIdToken = rawIDToken
}

// implements identity.State behaviour
func (x *IDPSession) MarshalJSON() ([]byte, error) {
	return json.Marshal(x.GetClaims().AsMap())
}

// implements identity.State behaviour
func (x *IDPSession) UnmarshalJSON(data []byte) error {
	if x == nil {
		return nil
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if len(raw) == 0 {
		return nil
	}

	merged := x.GetClaims().AsMap()
	if merged == nil {
		merged = make(map[string]any, len(raw))
	}
	for k, v := range mapsutil.Flatten(raw) {
		merged[k] = v
	}

	claims, err := structpb.NewStruct(merged)
	if err != nil {
		return err
	}
	x.Claims = claims

	return nil
}

// ErrSessionExpired indicates the session has expired
var ErrSessionExpired = fmt.Errorf("session has expired")

// Validate returns an error if the idpsession is not valid.
func (x *IDPSession) Validate() error {
	now := time.Now()
	if st := x.GetState(); st.GetState() == UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID {
		if st.GetDetails() != "" {
			return fmt.Errorf("idpsession no longer valid : %s", st.GetDetails())
		}
		return fmt.Errorf("idpsession no longer valid")
	}

	if token := x.GetOauthToken(); token != nil {
		if expiresAt := token.GetExpiresAt(); expiresAt.AsTime().Year() > 1970 && now.After(expiresAt.AsTime()) {
			return fmt.Errorf("%w: access_token expired at %s", ErrSessionExpired, expiresAt.AsTime())
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
