package sessions

import (
	"fmt"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/hashutil"
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
	// At_hash is an OPTIONAL Access Token hash value
	// https://ldapwiki.com/wiki/At_hash
	AccessTokenHash string `json:"at_hash,omitempty"`

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
}

// NewSession updates issuer, audience, and issuance timestamps but keeps
// parent expiry.
func NewSession(s *State, issuer string, audience []string, accessToken *oauth2.Token) State {
	newState := *s
	newState.IssuedAt = jwt.NewNumericDate(timeNow())
	newState.NotBefore = newState.IssuedAt
	newState.Audience = audience
	newState.Issuer = issuer
	newState.AccessTokenHash = fmt.Sprintf("%x", hashutil.Hash(accessToken))
	newState.Expiry = jwt.NewNumericDate(accessToken.Expiry)
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
