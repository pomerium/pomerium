// Package mock provides a mock implementation of session store and loader.
package mock // import "github.com/pomerium/pomerium/internal/sessions/mock"

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/sessions"
)

var _ sessions.SessionStore = &Store{}
var _ sessions.SessionLoader = &Store{}

// Store is a mock implementation of the SessionStore interface
type Store struct {
	ResponseSession string
	SessionJWT      string
	Session         *sessions.State
	SaveError       error
	LoadError       error
}

// ClearSession clears the ResponseSession
func (ms *Store) ClearSession(http.ResponseWriter, *http.Request) {
	ms.ResponseSession = ""
}

// LoadSession returns the session and a error
func (ms Store) LoadSession(*http.Request) (*sessions.State, string, error) {
	return ms.Session, ms.SessionJWT, ms.LoadError
}

// SaveSession returns a save error.
func (ms Store) SaveSession(http.ResponseWriter, *http.Request, interface{}) error {
	return ms.SaveError
}
