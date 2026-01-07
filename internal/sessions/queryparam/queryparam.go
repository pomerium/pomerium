// Package queryparam provides a query param based implementation of a session
// handle reader.
package queryparam

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

type handleReader struct {
	decoder encoding.Unmarshaler
}

// New returns a new HandleReader that reads session handles from query params.
func New(decoder encoding.Unmarshaler) sessions.HandleReader {
	return &handleReader{decoder: decoder}
}

// ReadSessionHandle reads a session handle from url query parameters.
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

// ReadSessionHandleJWT tries to retrieve the session handle jwt from URL
// query parameters.
func (hr *handleReader) ReadSessionHandleJWT(r *http.Request) ([]byte, error) {
	jwt := r.URL.Query().Get(urlutil.QuerySession)
	if jwt == "" {
		return nil, sessions.ErrNoSessionFound
	}
	return []byte(jwt), nil
}
