package authenticate

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/pomerium/pomerium/internal/log"
)

const (
	csrfTokenLength  = 32
	csrfCookieMaxAge = 12 * 3600 // 12 hours
)

var (
	errNoCSRFCookie = errors.New("no CSRF cookie")
)

type csrfCookieValidation struct {
	sc       *securecookie.SecureCookie
	name     string
	sameSite http.SameSite
}

func NewCSRFCookieValidation(
	authKey []byte, name string, sameSite http.SameSite,
) *csrfCookieValidation {
	sc := securecookie.New(authKey, nil)
	sc.SetSerializer(securecookie.JSONEncoder{})
	sc.MaxAge(csrfCookieMaxAge)

	return &csrfCookieValidation{
		sc:       sc,
		name:     name,
		sameSite: sameSite,
	}
}

// getTokenFromCookie returns the CSRF token stored in the cookie, or nil if no such cookie.
// Returns a non-nil error if a cookie exists but could not be decoded.
func (c *csrfCookieValidation) getTokenFromCookie(r *http.Request) ([]byte, error) {
	cookie, err := r.Cookie(c.name)
	if err != nil {
		return nil, errNoCSRFCookie
	}

	// TODO: check cookie is not just about to expire?

	var token []byte
	err = c.sc.Decode(c.name, cookie.Value, &token)
	if err != nil {
		return nil, err
	}

	if len(token) != csrfTokenLength {
		return nil, fmt.Errorf("unexpected length (want %d, got %d)", csrfTokenLength, len(token))
	}

	return token, nil
}

func (c *csrfCookieValidation) setNewCookie(w http.ResponseWriter, token []byte) error {
	encoded, err := c.sc.Encode(c.name, token)
	if err != nil {
		return err
	}

	cookie := &http.Cookie{
		Name:     c.name,
		Value:    encoded,
		MaxAge:   csrfCookieMaxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: c.sameSite,
		Path:     "/",
		Expires:  time.Now().Add(time.Duration(csrfCookieMaxAge) * time.Second),
	}
	http.SetCookie(w, cookie)
	return nil
}

// EnsureCookieSet will set a CSRF cookie on the response if one is not already
// present on the request, and return the new or existing CSRF token (base64-encoded).
func (c *csrfCookieValidation) EnsureCookieSet(w http.ResponseWriter, r *http.Request) string {
	token, err := c.getTokenFromCookie(r)
	if err != nil {
		if err != errNoCSRFCookie {
			log.Ctx(r.Context()).Info().Err(err).Msg("malformed CSRF token")
		}

		token = make([]byte, csrfTokenLength)
		rand.Read(token) // as of Go 1.24.0 this cannot return an error

		err = c.setNewCookie(w, token)
		if err != nil {
			log.Ctx(r.Context()).Error().Err(err).Msg("couldn't set CSRF cookie")
		}
	}

	return base64.StdEncoding.EncodeToString(token)
}

func (c *csrfCookieValidation) ValidateToken(r *http.Request, expected string) error {
	decoded, err := base64.StdEncoding.DecodeString(expected)
	if err != nil {
		return err
	}
	token, err := c.getTokenFromCookie(r)
	if err != nil {
		return err
	} else if !bytes.Equal(token, decoded) {
		return errors.New("invalid CSRF token")
	}
	return nil
}
