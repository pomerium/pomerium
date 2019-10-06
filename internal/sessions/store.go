package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"errors"
	"net/http"
)

var (
	// ErrExpired is the error for an expired session.
	ErrExpired = errors.New("internal/sessions: session is expired")
	// ErrNoSessionFound is the error for when no session is found.
	ErrNoSessionFound = errors.New("internal/sessions: session is not found")
	// ErrMalformed is the error for when a session is found but is malformed.
	ErrMalformed = errors.New("internal/sessions: session is malformed")
)

// SessionStore has the functions for setting, getting, and clearing the Session cookie
type SessionStore interface {
	ClearSession(http.ResponseWriter, *http.Request)
	LoadSession(*http.Request) (*State, error)
	SaveSession(http.ResponseWriter, *http.Request, *State) error
}

// SessionLoader is implemented by any struct that loads a pomerium session
// given a request, and returns a user state.
type SessionLoader interface {
	LoadSession(*http.Request) (*State, error)
}
