// Package header provides a request header based implementation of a
// session handle reader.
package header

import (
	"net/http"
	"slices"

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
	jwt := TokenFromHeaders(r.Header)
	if jwt == "" {
		return nil, sessions.ErrNoSessionFound
	}
	return []byte(jwt), nil
}

// credentialForms are the header forms a Pomerium JWT can be presented in, in
// order of precedence. Each form names the canonical header that carries it
// and extracts the JWT from that header's value.
var credentialForms = []struct {
	header string
	jwt    func(value string) (string, bool)
}{
	// X-Pomerium-Authorization: <JWT>
	{httputil.CanonicalHeaderKey(httputil.HeaderPomeriumAuthorization), func(value string) (string, bool) {
		return value, value != ""
	}},
	// Authorization: Pomerium <JWT>
	{httputil.HeaderAuthorization, httputil.PomeriumAuthorizationToken},
	// Authorization: Bearer Pomerium-<JWT>
	{httputil.HeaderAuthorization, httputil.PomeriumBearerToken},
}

// TokenFromHeaders retrieves the value of the authorization header(s) from a given
// request and authentication type.
func TokenFromHeaders(header http.Header) string {
	for _, f := range credentialForms {
		if jwt, ok := f.jwt(header.Get(f.header)); ok {
			return jwt
		}
	}
	return ""
}

// CredentialHeaders returns the canonical names of the headers that carry a
// Pomerium JWT in any form TokenFromHeaders accepts. get returns the value of
// the header with the given canonical name.
func CredentialHeaders(get func(name string) string) []string {
	var names []string
	for _, f := range credentialForms {
		if _, ok := f.jwt(get(f.header)); ok && !slices.Contains(names, f.header) {
			names = append(names, f.header)
		}
	}
	return names
}
