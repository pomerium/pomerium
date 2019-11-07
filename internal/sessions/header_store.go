package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"net/http"
	"strings"

	"github.com/pomerium/pomerium/internal/encoding"
)

const (
	defaultAuthHeader = "Authorization"
	defaultAuthType   = "Bearer"
)

// HeaderStore implements the load session store interface using http
// authorization headers.
type HeaderStore struct {
	authHeader string
	authType   string
	encoder    encoding.Unmarshaler
}

// NewHeaderStore returns a new header store for loading sessions from
// authorization header as defined in as defined in rfc2617
//
// NOTA BENE: While most servers do not log Authorization headers by default,
// you should ensure no other services are logging or leaking your auth headers.
func NewHeaderStore(enc encoding.Unmarshaler, headerType string) *HeaderStore {
	if headerType == "" {
		headerType = defaultAuthType
	}
	return &HeaderStore{
		authHeader: defaultAuthHeader,
		authType:   headerType,
		encoder:    enc,
	}
}

// LoadSession tries to retrieve the token string from the Authorization header.
func (as *HeaderStore) LoadSession(r *http.Request) (*State, error) {
	cipherText := TokenFromHeader(r, as.authHeader, as.authType)
	if cipherText == "" {
		return nil, ErrNoSessionFound
	}
	var session State
	if err := as.encoder.Unmarshal([]byte(cipherText), &session); err != nil {
		return nil, ErrMalformed
	}
	return &session, nil
}

// TokenFromHeader retrieves the value of the authorization header from a given
// request, header key, and authentication type.
func TokenFromHeader(r *http.Request, authHeader, authType string) string {
	bearer := r.Header.Get(authHeader)
	atSize := len(authType)
	if len(bearer) > atSize && strings.EqualFold(bearer[0:atSize], authType) {
		return bearer[atSize+1:]
	}
	return ""
}
