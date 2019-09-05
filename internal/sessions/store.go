package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"errors"
	"net/http"
)

// ErrEmptySession is an error for an empty sessions.
var ErrEmptySession = errors.New("internal/sessions: empty session")

// ErrEmptyCSRF is an error for an empty sessions.
var ErrEmptyCSRF = errors.New("internal/sessions: empty csrf")

// CSRFStore has the functions for setting, getting, and clearing the CSRF cookie
type CSRFStore interface {
	SetCSRF(http.ResponseWriter, *http.Request, string)
	GetCSRF(*http.Request) (*http.Cookie, error)
	ClearCSRF(http.ResponseWriter, *http.Request)
}

// SessionStore has the functions for setting, getting, and clearing the Session cookie
type SessionStore interface {
	ClearSession(http.ResponseWriter, *http.Request)
	LoadSession(*http.Request) (*State, error)
	SaveSession(http.ResponseWriter, *http.Request, *State) error
}
