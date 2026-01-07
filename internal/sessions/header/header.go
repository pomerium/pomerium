// Package header provides a request header based implementation of a
// session handle reader.
package header

import (
	"net/http"
	"strings"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

type handleReader struct {
	decoder encoding.Unmarshaler
}

// New returns a new session HandleReader that reads session handles from
// http headers.
func New(decoder encoding.Unmarshaler) sessions.HandleReader {
	return &handleReader{decoder: decoder}
}

// ReadSessionHandle reads a session handle from http headers.
func (hr *handleReader) ReadSessionHandle(r *http.Request) (*session.Handle, error) {
	rawJWT, err := hr.ReadSessionHandleJWT(r)
	if err != nil {
		return nil, err
	}
	var h session.Handle
	err = hr.decoder.Unmarshal(rawJWT, &h)
	if err != nil {
		return nil, err
	}
	return &h, nil
}

// ReadSessionHandle reads a session handle jwt from http headers.
func (hr *handleReader) ReadSessionHandleJWT(r *http.Request) ([]byte, error) {
	jwt := TokenFromHeaders(r)
	if jwt == "" {
		return nil, sessions.ErrNoSessionFound
	}
	return []byte(jwt), nil
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
