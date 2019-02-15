package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"net/http"
)

// MockCSRFStore is a mock implementation of the CSRF store interface
type MockCSRFStore struct {
	ResponseCSRF string
	Cookie       *http.Cookie
	GetError     error
}

// SetCSRF sets the ResponseCSRF string to a val
func (ms MockCSRFStore) SetCSRF(rw http.ResponseWriter, req *http.Request, val string) {
	ms.ResponseCSRF = val
}

// ClearCSRF clears the ResponseCSRF string
func (ms MockCSRFStore) ClearCSRF(http.ResponseWriter, *http.Request) {
	ms.ResponseCSRF = ""
}

// GetCSRF returns the cookie and error
func (ms MockCSRFStore) GetCSRF(*http.Request) (*http.Cookie, error) {
	return ms.Cookie, ms.GetError
}

// MockSessionStore is a mock implementation of the SessionStore interface
type MockSessionStore struct {
	ResponseSession string
	Session         *SessionState
	SaveError       error
	LoadError       error
}

// ClearSession clears the ResponseSession
func (ms *MockSessionStore) ClearSession(http.ResponseWriter, *http.Request) {
	ms.ResponseSession = ""
}

// LoadSession returns the session and a error
func (ms MockSessionStore) LoadSession(*http.Request) (*SessionState, error) {
	return ms.Session, ms.LoadError
}

// SaveSession returns a save error.
func (ms MockSessionStore) SaveSession(http.ResponseWriter, *http.Request, *SessionState) error {
	return ms.SaveError
}
