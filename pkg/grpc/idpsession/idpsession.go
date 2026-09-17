package idpsession

import (
	"encoding/json"
	"fmt"
	"time"

	structpb "google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/pkg/mapsutil"
)

// implements identity.State
func (x *IDPSession) SetRawIDToken(rawIDToken string) {
	if x == nil {
		return
	}
	x.RawIdToken = rawIDToken
	if idToken, err := ParseIDToken(rawIDToken); err == nil && idToken != nil {
		x.IdToken = idToken
	}
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
	// same as pkg/identity/manager/data.go#104
	// To preserve existing behavior: filter out claims not related to user info.
	delete(raw, "iss")
	delete(raw, "sub")
	delete(raw, "exp")
	delete(raw, "iat")
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

	if token := x.GetOauthToken(); token != nil {
		if expiresAt := token.GetExpiresAt(); expiresAt.AsTime().Year() > 1970 && now.After(expiresAt.AsTime()) {
			return fmt.Errorf("%w: access_token expired at %s", ErrSessionExpired, expiresAt.AsTime())
		}
	}

	return nil
}
