// Package mock provides a mock implementation of session store and loader.
package mock

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/sessions"
)

var (
	_ sessions.SessionStore  = &Store{}
	_ sessions.SessionLoader = &Store{}
)

// Store is a mock implementation of the SessionStore interface
type Store struct {
	ResponseSession string
	SessionHandle   *sessions.Handle
	SaveError       error
	LoadError       error
	Secret          []byte
	Encrypted       bool
}

// ClearSession clears the ResponseSession
func (ms *Store) ClearSession(http.ResponseWriter, *http.Request) {
	ms.ResponseSession = ""
}

// LoadSession returns the session and a error
func (ms Store) LoadSession(*http.Request) (string, error) {
	var signer encoding.MarshalUnmarshaler
	signer, _ = jws.NewHS256Signer(ms.Secret)
	jwt, _ := signer.Marshal(ms.SessionHandle)
	return string(jwt), ms.LoadError
}

// SaveSession returns a save error.
func (ms Store) SaveSession(http.ResponseWriter, *http.Request, any) error {
	return ms.SaveError
}
