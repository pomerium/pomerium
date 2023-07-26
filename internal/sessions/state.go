package sessions

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
)

// ErrMissingID is the error for a session state that has no ID set.
var ErrMissingID = errors.New("invalid session: missing id")

// timeNow is time.Now but pulled out as a variable for tests.
var timeNow = time.Now

// State is our object that keeps track of a user's session state
type State struct {
	// Public claim values (as specified in RFC 7519).
	Issuer   string           `json:"iss,omitempty"`
	Subject  string           `json:"sub,omitempty"`
	Audience jwt.Audience     `json:"aud,omitempty"`
	IssuedAt *jwt.NumericDate `json:"iat,omitempty"`
	ID       string           `json:"jti,omitempty"`

	// Azure returns OID which should be used instead of subject.
	OID string `json:"oid,omitempty"`

	// DatabrokerServerVersion tracks the last referenced databroker server version
	// for the saved session.
	DatabrokerServerVersion uint64 `json:"databroker_server_version,omitempty"`
	// DatabrokerRecordVersion tracks the last referenced databroker record version
	// for the saved session.
	DatabrokerRecordVersion uint64 `json:"databroker_record_version,omitempty"`

	// IdentityProviderID is the identity provider for the session.
	IdentityProviderID string `json:"idp_id,omitempty"`
}

// NewState creates a new State.
func NewState(idpID string) *State {
	return &State{
		IssuedAt:           jwt.NewNumericDate(timeNow()),
		ID:                 uuid.NewString(),
		IdentityProviderID: idpID,
	}
}

// WithNewIssuer creates a new State from an existing State.
func (s *State) WithNewIssuer(issuer string, audience []string) State {
	newState := State{}
	if s != nil {
		newState = *s
	}
	newState.IssuedAt = jwt.NewNumericDate(timeNow())
	newState.Audience = audience
	newState.Issuer = issuer
	return newState
}

// UserID returns the corresponding user ID for a session.
func (s *State) UserID() string {
	if s.OID != "" {
		return s.OID
	}
	return s.Subject
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
