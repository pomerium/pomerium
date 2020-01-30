// Package sessions handles the storage, management, and validation
// of pomerium user sessions.
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

// SessionLoader defines an interface for loading a session.
type SessionLoader interface {
	LoadSession(*http.Request) (*State, string, error)
}
