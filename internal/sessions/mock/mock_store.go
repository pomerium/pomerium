// Package mock provides a mock implementation of session store and loader.
package mock

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

var (
	_ sessions.HandleWriter = &Store{}
	_ sessions.HandleReader = &Store{}
)

// Store is a mock implementation of the HandleReaderWriter interface.
type Store struct {
	ResponseSession string
	SessionHandle   *session.Handle
	SaveError       error
	LoadError       error
	Secret          []byte
	Encrypted       bool
}

// ClearSessionHandle clears the ResponseSession.
func (ms *Store) ClearSessionHandle(http.ResponseWriter) {
	ms.ResponseSession = ""
}

// ReadSessionHandle returns the session and an error.
func (ms Store) ReadSessionHandle(*http.Request) (*session.Handle, error) {
	return ms.SessionHandle, ms.LoadError
}

// ReadSessionHandleJWT returns the session jwt and an error.
func (ms Store) ReadSessionHandleJWT(*http.Request) ([]byte, error) {
	var signer encoding.MarshalUnmarshaler
	signer, _ = jws.NewHS256Signer(ms.Secret)
	jwt, _ := signer.Marshal(ms.SessionHandle)
	return jwt, ms.LoadError
}

// WriteSessionHandle returns a save error.
func (ms Store) WriteSessionHandle(http.ResponseWriter, *session.Handle) error {
	return ms.SaveError
}

// WriteSessionHandleJWT returns a save error.
func (ms Store) WriteSessionHandleJWT(http.ResponseWriter, []byte) error {
	return ms.SaveError
}
