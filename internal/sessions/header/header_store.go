// Package header provides a request header based implementation of a
// session loader.
package header // import "github.com/pomerium/pomerium/internal/sessions/header"

import (
	"net/http"
	"strings"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/sessions"
)

var _ sessions.SessionLoader = &Store{}

const (
	defaultAuthHeader = "Authorization"
	defaultAuthType   = "Bearer"
)

// Store implements the load session store interface using http
// authorization headers.
type Store struct {
	authHeader string
	authType   string
	encoder    encoding.Unmarshaler
}

// NewStore returns a new header store for loading sessions from
// authorization header as defined in as defined in rfc2617
//
// NOTA BENE: While most servers do not log Authorization headers by default,
// you should ensure no other services are logging or leaking your auth headers.
func NewStore(enc encoding.Unmarshaler, headerType string) *Store {
	if headerType == "" {
		headerType = defaultAuthType
	}
	return &Store{
		authHeader: defaultAuthHeader,
		authType:   headerType,
		encoder:    enc,
	}
}

// LoadSession tries to retrieve the token string from the Authorization header.
func (as *Store) LoadSession(r *http.Request) (*sessions.State, string, error) {
	jwt := TokenFromHeader(r, as.authHeader, as.authType)
	if jwt == "" {
		return nil, "", sessions.ErrNoSessionFound
	}
	var session sessions.State
	if err := as.encoder.Unmarshal([]byte(jwt), &session); err != nil {
		return nil, "", sessions.ErrMalformed
	}
	return &session, jwt, nil
}

// TokenFromHeader retrieves the value of the authorization header from a given
// request, header key, and authentication type.
func TokenFromHeader(r *http.Request, authHeader, authType string) string {
	bearer := r.Header.Get(authHeader)
	atSize := len(authType)
	if len(bearer) > atSize && strings.EqualFold(bearer[0:atSize], authType) {
		return bearer[atSize+1:]
	}
	return ""
}
