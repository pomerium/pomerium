// Package header provides a request header based implementation of a
// session loader.
package header

import (
	"context"
	"net/http"
	"strings"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
)

var _ sessions.SessionLoader = &Store{}

// Store implements the load session store interface using http
// authorization headers.
type Store struct {
	encoder encoding.Unmarshaler
}

// NewStore returns a new header store for loading sessions from
// authorization header as defined in as defined in rfc2617
//
// NOTA BENE: While most servers do not log Authorization headers by default,
// you should ensure no other services are logging or leaking your auth headers.
func NewStore(enc encoding.Unmarshaler) *Store {
	return &Store{
		encoder: enc,
	}
}

// LoadSession tries to retrieve the token string from the Authorization header.
func (as *Store) LoadSession(_ context.Context, r *http.Request) (string, error) {
	jwt := TokenFromHeaders(r)
	if jwt == "" {
		return "", sessions.ErrNoSessionFound
	}
	return jwt, nil
}

// TokenFromHeaders retrieves the value of the authorization header(s) from a given
// request and authentication type.
func TokenFromHeaders(r *http.Request) string {
	// X-Pomerium-Authorization: <JWT>
	if jwt := r.Header.Get(httputil.HeaderPomeriumAuthorization); jwt != "" {
		return jwt
	}

	bearer := r.Header.Get(httputil.HeaderAuthorization)
	// Authorization: Pomerium <JWT>
	prefix := httputil.AuthorizationTypePomerium + " "
	if strings.HasPrefix(bearer, prefix) {
		return bearer[len(prefix):]
	}

	// Authorization: Bearer Pomerium-<JWT>
	prefix = "Bearer " + httputil.AuthorizationTypePomerium + "-"
	if strings.HasPrefix(bearer, prefix) {
		return bearer[len(prefix):]
	}

	return ""
}
