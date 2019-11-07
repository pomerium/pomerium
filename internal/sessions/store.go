package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"errors"
	"net/http"
)

var (
	// ErrNoSessionFound is the error for when no session is found.
	ErrNoSessionFound = errors.New("internal/sessions: session is not found")

	// ErrMalformed is the error for when a session is found but is malformed.
	ErrMalformed = errors.New("internal/sessions: session is malformed")

	// ErrNotValidYet indicates that token is used before time indicated in nbf claim.
	ErrNotValidYet = errors.New("internal/sessions: validation failed, token not valid yet (nbf)")

	// ErrExpired indicates that token is used after expiry time indicated in exp claim.
	ErrExpired = errors.New("internal/sessions: validation failed, token is expired (exp)")

	// ErrIssuedInTheFuture indicates that the iat field is in the future.
	ErrIssuedInTheFuture = errors.New("internal/sessions: validation field, token issued in the future (iat)")

	// ErrInvalidAudience indicated invalid aud claim.
	ErrInvalidAudience = errors.New("internal/sessions: validation failed, invalid audience claim (aud)")
)

// SessionStore has the functions for setting, getting, and clearing the Session cookie
type SessionStore interface {
	ClearSession(http.ResponseWriter, *http.Request)
	SessionLoader
	SaveSession(http.ResponseWriter, *http.Request, interface{}) error
}

// SessionLoader is implemented by any struct that loads a pomerium session
// given a request, and returns a user state.
type SessionLoader interface {
	LoadSession(*http.Request) (*State, error)
}

// Encoder can both Marshal and Unmarshal a struct into and from a set of bytes.
type Encoder interface {
	Marshaler
	Unmarshaler
}

// Marshaler encodes a struct into a set of bytes.
type Marshaler interface {
	Marshal(interface{}) ([]byte, error)
}

// Unmarshaler decodes a set of bytes and returns a struct.
type Unmarshaler interface {
	Unmarshal([]byte, interface{}) error
}
