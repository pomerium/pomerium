package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"errors"
	"net/http"
)

// ErrEmptySession is an error for an empty sessions.
var ErrEmptySession = errors.New("internal/sessions: empty session")

// SessionStore has the functions for setting, getting, and clearing the Session cookie
type SessionStore interface {
	ClearSession(http.ResponseWriter, *http.Request)
	LoadSession(*http.Request) (*State, error)
	SaveSession(http.ResponseWriter, *http.Request, *State) error
}
