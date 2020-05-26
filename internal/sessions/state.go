package sessions

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cespare/xxhash/v2"
	oidc "github.com/coreos/go-oidc"
	"github.com/mitchellh/hashstructure"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2/jwt"
)

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

	// core pomerium identity claims ; not standard to RFC 7519
	Email  string   `json:"email"`
	Groups []string `json:"groups,omitempty"`
	User   string   `json:"user,omitempty"` // google

	// commonly supported IdP information
	// https://www.iana.org/assignments/jwt/jwt.xhtml#claims
	Name          string `json:"name,omitempty"`           // google
	GivenName     string `json:"given_name,omitempty"`     // google
	FamilyName    string `json:"family_name,omitempty"`    // google
	Picture       string `json:"picture,omitempty"`        // google
	EmailVerified bool   `json:"email_verified,omitempty"` // google

	// Impersonate-able fields
	ImpersonateEmail  string   `json:"impersonate_email,omitempty"`
	ImpersonateGroups []string `json:"impersonate_groups,omitempty"`

	// Programmatic whether this state is used for machine-to-machine
	// programatic access.
	Programmatic bool `json:"programatic"`

	AccessToken   *oauth2.Token `json:"act,omitempty"`
	AccessTokenID string        `json:"ati,omitempty"`

	idToken *oidc.IDToken
}

// NewStateFromTokens returns a session state built from oidc and oauth2
// tokens as part of OpenID Connect flow with a new audience appended to the
// audience claim.
func NewStateFromTokens(idToken *oidc.IDToken, accessToken *oauth2.Token, audience string) (*State, error) {
	if idToken == nil {
		return nil, errors.New("sessions: oidc id token missing")
	}
	if accessToken == nil {
		return nil, errors.New("sessions: oauth2 token missing")
	}
	s := &State{}
	if err := idToken.Claims(s); err != nil {
		return nil, fmt.Errorf("sessions: couldn't unmarshal extra claims %w", err)
	}
	s.Audience = []string{audience}
	s.idToken = idToken
	s.AccessToken = accessToken
	s.AccessTokenID = s.accessTokenHash()
	return s, nil
}

// UpdateState updates the current state given a new identity (oidc) and authorization
// (oauth2) tokens following a oidc refresh. NB, unlike during authentication,
// refresh typically provides fewer claims in the token so we want to build from
// our previous state.
func (s *State) UpdateState(idToken *oidc.IDToken, accessToken *oauth2.Token) error {
	if idToken == nil {
		return errors.New("sessions: oidc id token missing")
	}
	if accessToken == nil {
		return errors.New("sessions: oauth2 token missing")
	}
	audience := append(s.Audience[:0:0], s.Audience...)
	s.AccessToken = accessToken
	if err := idToken.Claims(s); err != nil {
		return fmt.Errorf("sessions: update state failed %w", err)
	}
	s.Audience = audience
	s.Expiry = jwt.NewNumericDate(accessToken.Expiry)
	s.AccessTokenID = s.accessTokenHash()
	return nil
}

// NewSession updates issuer, audience, and issuance timestamps but keeps
// parent expiry.
func (s State) NewSession(issuer string, audience []string) *State {
	s.IssuedAt = jwt.NewNumericDate(timeNow())
	s.NotBefore = s.IssuedAt
	s.Audience = audience
	s.Issuer = issuer
	return &s
}

// RouteSession creates a route session with access tokens stripped.
func (s State) RouteSession() *State {
	s.AccessToken = nil
	return &s
}

// IsExpired returns true if the users's session is expired.
func (s *State) IsExpired() bool {

	if s.Expiry != nil && timeNow().After(s.Expiry.Time()) {
		return true
	}

	if s.AccessToken != nil && timeNow().After(s.AccessToken.Expiry) {
		return true
	}

	return false
}

// Impersonating returns if the request is impersonating.
func (s *State) Impersonating() bool {
	return s.ImpersonateEmail != "" || len(s.ImpersonateGroups) != 0
}

// RequestEmail is the email to make the request as.
func (s *State) RequestEmail() string {
	if s.ImpersonateEmail != "" {
		return s.ImpersonateEmail
	}
	return s.Email
}

// RequestGroups returns the groups of the Groups making the request; uses
// impersonating user if set.
func (s *State) RequestGroups() string {
	if len(s.ImpersonateGroups) != 0 {
		return strings.Join(s.ImpersonateGroups, ",")
	}
	return strings.Join(s.Groups, ",")
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

func (s *State) accessTokenHash() string {
	hash, err := hashstructure.Hash(
		s.AccessToken,
		&hashstructure.HashOptions{Hasher: xxhash.New()})
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", hash)
}

// UnmarshalJSON parses the JSON-encoded session state.
// TODO(BDD): remove in v0.8.0
func (s *State) UnmarshalJSON(b []byte) error {
	type Alias State
	t := &struct {
		*Alias
		OldToken *oauth2.Token `json:"access_token,omitempty"` // < v0.5.0
	}{
		Alias: (*Alias)(s),
	}
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	if t.AccessToken == nil {
		t.AccessToken = t.OldToken
	}
	if t.User == "" {
		t.User = t.Subject
	}
	return nil
}
