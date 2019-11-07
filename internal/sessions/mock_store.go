package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"net/http"
)

// MockSessionStore is a mock implementation of the SessionStore interface
type MockSessionStore struct {
	ResponseSession string
	Session         *State
	SaveError       error
	LoadError       error
}

// ClearSession clears the ResponseSession
func (ms *MockSessionStore) ClearSession(http.ResponseWriter, *http.Request) {
	ms.ResponseSession = ""
}

// LoadSession returns the session and a error
func (ms MockSessionStore) LoadSession(*http.Request) (*State, error) {
	return ms.Session, ms.LoadError
}

// SaveSession returns a save error.
func (ms MockSessionStore) SaveSession(http.ResponseWriter, *http.Request, interface{}) error {
	return ms.SaveError
}
