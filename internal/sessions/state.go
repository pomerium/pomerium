package sessions

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// ErrMissingID is the error for a session state that has no ID set.
var ErrMissingID = errors.New("invalid session: missing id")

// timeNow is time.Now but pulled out as a variable for tests.
var timeNow = time.Now

// Version represents "ver" field in JWT public claims.
//
// The field is not specified by RFC 7519, so providers can
// return either string or number (like okta).
type Version string

// String implements fmt.Stringer interface.
func (v *Version) String() string {
	return string(*v)
}

// UnmarshalJSON implements json.Unmarshaler interface.
func (v *Version) UnmarshalJSON(b []byte) error {
	var tmp interface{}
	if err := json.Unmarshal(b, &tmp); err != nil {
		return err
	}
	switch val := tmp.(type) {
	case string:
		*v = Version(val)
	case float64:
		*v = Version(fmt.Sprintf("%g", val))
	default:
		return errors.New("invalid type for Version")
	}
	return nil
}

// State is our object that keeps track of a user's session state
type State struct {
	// Public claim values (as specified in RFC 7519).
	Issuer    string           `json:"iss,omitempty"`
	Subject   string           `json:"sub,omitempty"`
	Audience  jwt.Audience     `json:"aud,omitempty"`
	Expiry    *jwt.NumericDate `json:"exp,omitempty"`
	NotBefore *jwt.NumericDate `json:"nbf,omitempty"`
	IssuedAt  *jwt.NumericDate `json:"iat,omitempty"`
	ID        string           `json:"jti,omitempty"`

	// "ver" field is not standard, but is supported by most providers.
	Version Version `json:"ver,omitempty"`

	// Azure returns OID which should be used instead of subject.
	OID string `json:"oid,omitempty"`

	// Programmatic whether this state is used for machine-to-machine
	// programmatic access.
	Programmatic bool `json:"programmatic"`
}

// NewSession updates issuer, audience, and issuance timestamps but keeps
// parent expiry.
func NewSession(s *State, issuer string, audience []string) State {
	newState := *s
	newState.IssuedAt = jwt.NewNumericDate(timeNow())
	newState.NotBefore = newState.IssuedAt
	newState.Audience = audience
	newState.Issuer = issuer
	return newState
}

// IsExpired returns true if the users's session is expired.
func (s *State) IsExpired() bool {
	return s.Expiry != nil && timeNow().After(s.Expiry.Time())
}

// UserID returns the corresponding user ID for a session.
func (s *State) UserID(provider string) string {
	if s.OID != "" {
		return databroker.GetUserID(provider, s.OID)
	}
	return databroker.GetUserID(provider, s.Subject)
}

// UnmarshalJSON returns a State struct from JSON. Additionally munges
// a user's session by using by setting `user` claim to `sub` if empty.
func (s *State) UnmarshalJSON(data []byte) error {
	type StateAlias State
	a := &struct {
		*StateAlias
	}{
		StateAlias: (*StateAlias)(s),
	}

	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}

	if s.ID == "" {
		return ErrMissingID
	}

	return nil
}
