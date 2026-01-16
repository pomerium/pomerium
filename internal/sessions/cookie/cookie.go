// Package cookie provides a cookie based session handle reader/writer.
package cookie

import (
	"net/http"
	"time"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

// Options holds options for the handle reader/writer
type Options struct {
	Name     string
	Domain   string
	Expire   time.Duration
	HTTPOnly bool
	Secure   bool
	SameSite http.SameSite
}

// A GetOptionsFunc is a getter for cookie options.
type GetOptionsFunc func() Options

// handleReaderWriter implements the HandleReaderWriter interface using cookies.
type handleReaderWriter struct {
	getOptions GetOptionsFunc
	encoder    encoding.MarshalUnmarshaler
}

// New returns a new session handle reader/writer using cookies.
func New(getOptions GetOptionsFunc, encoder encoding.MarshalUnmarshaler) (sessions.HandleReaderWriter, error) {
	cs := &handleReaderWriter{getOptions: getOptions}
	cs.encoder = encoder
	return cs, nil
}

func (hrw *handleReaderWriter) makeCookie(value string) *http.Cookie {
	opts := hrw.getOptions()
	return &http.Cookie{
		Name:     opts.Name,
		Value:    value,
		Path:     "/",
		Domain:   opts.Domain,
		HttpOnly: opts.HTTPOnly,
		Secure:   opts.Secure,
		Expires:  time.Now().Add(opts.Expire),
		SameSite: opts.SameSite,
	}
}

// ClearSessionHandle clears the session handle cookie from a request
func (hrw *handleReaderWriter) ClearSessionHandle(w http.ResponseWriter) {
	c := hrw.makeCookie("")
	c.MaxAge = -1
	c.Expires = time.Now().Add(-time.Hour)
	http.SetCookie(w, c)
}

// ReadSessionHandle returns a session handle from the cookie in the request.
func (hrw *handleReaderWriter) ReadSessionHandle(r *http.Request) (*session.Handle, error) {
	rawJWT, err := hrw.ReadSessionHandleJWT(r)
	if err != nil {
		return nil, err
	}
	var h session.Handle
	err = hrw.encoder.Unmarshal(rawJWT, &h)
	if err != nil {
		return nil, err
	}
	return &h, nil
}

// ReadSessionHandleJWT returns a session handle jwt from the cookie in the request.
func (hrw *handleReaderWriter) ReadSessionHandleJWT(r *http.Request) ([]byte, error) {
	opts := hrw.getOptions()
	for _, c := range r.CookiesNamed(opts.Name) {
		return []byte(c.Value), nil
	}
	return nil, sessions.ErrNoSessionFound
}

// WriteSessionHandle saves a session handle to a request's cookie store.
func (hrw *handleReaderWriter) WriteSessionHandle(w http.ResponseWriter, h *session.Handle) error {
	rawJWT, err := hrw.encoder.Marshal(h)
	if err != nil {
		return err
	}
	return hrw.WriteSessionHandleJWT(w, rawJWT)
}

// WriteSessionHandleJWT saves a session handle to a request's cookie store.
func (hrw *handleReaderWriter) WriteSessionHandleJWT(w http.ResponseWriter, rawJWT []byte) error {
	hrw.setSessionCookie(w, string(rawJWT))
	return nil
}

func (hrw *handleReaderWriter) setSessionCookie(w http.ResponseWriter, val string) {
	http.SetCookie(w, hrw.makeCookie(val))
}
