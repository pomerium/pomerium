package sessions

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
)

// ErrMissingID is the error for a session state that has no ID set.
var ErrMissingID = errors.New("invalid session: missing id")

// timeNow is time.Now but pulled out as a variable for tests.
var timeNow = time.Now

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
	Version   string           `json:"ver,omitempty"`

	// Impersonate-able fields
	ImpersonateEmail  string   `json:"impersonate_email,omitempty"`
	ImpersonateGroups []string `json:"impersonate_groups,omitempty"`

	// Programmatic whether this state is used for machine-to-machine
	// programatic access.
	Programmatic bool `json:"programatic"`
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

// Impersonating returns if the request is impersonating.
func (s *State) Impersonating() bool {
	return s.ImpersonateEmail != "" || len(s.ImpersonateGroups) != 0
}

// SetImpersonation sets impersonation user and groups.
func (s *State) SetImpersonation(email, groups string) {
	s.ImpersonateEmail = email
	if groups == "" {
		s.ImpersonateGroups = nil
	} else {
		s.ImpersonateGroups = strings.Split(groups, ",")
	}
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
