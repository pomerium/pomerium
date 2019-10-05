package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"net/http"
	"strings"

	"github.com/pomerium/pomerium/internal/cryptutil"
)

const (
	// defaultAuthHeader and defaultAuthType are default header name for the
	// authorization bearer  token header as defined in rfc2617
	// https://tools.ietf.org/html/rfc6750#section-2.1
	defaultAuthHeader = "Authorization"
	defaultAuthType   = "Bearer"
)

// HeaderStore implements the load session store interface using http
// authorization headers.
type HeaderStore struct {
	authHeader string
	authType   string
	encoder    cryptutil.SecureEncoder
}

// NewHeaderStore returns a new header store for loading sessions from
// authorization headers.
func NewHeaderStore(enc cryptutil.SecureEncoder) *HeaderStore {
	return &HeaderStore{
		authHeader: defaultAuthHeader,
		authType:   defaultAuthType,
		encoder:    enc,
	}
}

// LoadSession tries to retrieve the token string from the Authorization header.
//
// NOTA BENE: While most servers do not log Authorization headers by default,
// you should ensure no other services are logging or leaking your auth headers.
func (as *HeaderStore) LoadSession(r *http.Request) (*State, error) {
	cipherText := as.tokenFromHeader(r)
	if cipherText == "" {
		return nil, ErrNoSessionFound
	}
	session, err := UnmarshalSession(cipherText, as.encoder)
	if err != nil {
		return nil, ErrMalformed
	}
	return session, nil

}

// retrieve the value of the authorization header
func (as *HeaderStore) tokenFromHeader(r *http.Request) string {
	bearer := r.Header.Get(as.authHeader)
	atSize := len(as.authType)
	if len(bearer) > atSize && strings.EqualFold(bearer[0:atSize], as.authType) {
		return bearer[atSize+1:]
	}
	return ""
}
