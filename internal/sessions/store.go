package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"net/http"
)

// SessionStore defines an interface for loading, saving, and clearing a session.
type SessionStore interface {
	SessionLoader
	ClearSession(http.ResponseWriter, *http.Request)
	SaveSession(http.ResponseWriter, *http.Request, interface{}) error
}

// SessionStore defines an interface for loading a session.
type SessionLoader interface {
	LoadSession(*http.Request) (*State, error)
}
