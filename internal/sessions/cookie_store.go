package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
)

// ErrInvalidSession is an error for invalid sessions.
var ErrInvalidSession = errors.New("invalid session")

// CSRFStore has the functions for setting, getting, and clearing the CSRF cookie
type CSRFStore interface {
	SetCSRF(http.ResponseWriter, *http.Request, string)
	GetCSRF(*http.Request) (*http.Cookie, error)
	ClearCSRF(http.ResponseWriter, *http.Request)
}

// SessionStore has the functions for setting, getting, and clearing the Session cookie
type SessionStore interface {
	ClearSession(http.ResponseWriter, *http.Request)
	LoadSession(*http.Request) (*SessionState, error)
	SaveSession(http.ResponseWriter, *http.Request, *SessionState) error
}

// CookieStore represents all the cookie related configurations
type CookieStore struct {
	Name               string
	CSRFCookieName     string
	CookieExpire       time.Duration
	CookieRefresh      time.Duration
	CookieSecure       bool
	CookieHTTPOnly     bool
	CookieDomain       string
	CookieCipher       cryptutil.Cipher
	SessionLifetimeTTL time.Duration
}

// CreateMiscreantCookieCipher creates a new miscreant cipher with the cookie secret
func CreateMiscreantCookieCipher(cookieSecret []byte) func(s *CookieStore) error {
	return func(s *CookieStore) error {
		cipher, err := cryptutil.NewCipher(cookieSecret)
		if err != nil {
			return fmt.Errorf("miscreant cookie-secret error: %s", err.Error())
		}
		s.CookieCipher = cipher
		return nil
	}
}

// NewCookieStore returns a new session with ciphers for each of the cookie secrets
func NewCookieStore(cookieName string, optFuncs ...func(*CookieStore) error) (*CookieStore, error) {
	c := &CookieStore{
		Name:           cookieName,
		CookieSecure:   true,
		CookieHTTPOnly: true,
		CookieExpire:   168 * time.Hour,
		CSRFCookieName: fmt.Sprintf("%v_%v", cookieName, "csrf"),
	}

	for _, f := range optFuncs {
		err := f(c)
		if err != nil {
			return nil, err
		}
	}

	return c, nil
}

func (s *CookieStore) makeCookie(req *http.Request, name string, value string, expiration time.Duration, now time.Time) *http.Cookie {
	domain := req.Host
	if h, _, err := net.SplitHostPort(domain); err == nil {
		domain = h
	}
	if s.CookieDomain != "" {
		domain = s.CookieDomain
	}

	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		HttpOnly: s.CookieHTTPOnly,
		Secure:   s.CookieSecure,
		Expires:  now.Add(expiration),
	}
}

// makeSessionCookie constructs a session cookie given the request, an expiration time and the current time.
func (s *CookieStore) makeSessionCookie(req *http.Request, value string, expiration time.Duration, now time.Time) *http.Cookie {
	return s.makeCookie(req, s.Name, value, expiration, now)
}

// makeCSRFCookie creates a CSRF cookie given the request, an expiration time, and the current time.
func (s *CookieStore) makeCSRFCookie(req *http.Request, value string, expiration time.Duration, now time.Time) *http.Cookie {
	return s.makeCookie(req, s.CSRFCookieName, value, expiration, now)
}

// ClearCSRF clears the CSRF cookie from the request
func (s *CookieStore) ClearCSRF(rw http.ResponseWriter, req *http.Request) {
	http.SetCookie(rw, s.makeCSRFCookie(req, "", time.Hour*-1, time.Now()))
}

// SetCSRF sets the CSRFCookie creates a CSRF cookie in a given request
func (s *CookieStore) SetCSRF(rw http.ResponseWriter, req *http.Request, val string) {
	http.SetCookie(rw, s.makeCSRFCookie(req, val, s.CookieExpire, time.Now()))
}

// GetCSRF gets the CSRFCookie creates a CSRF cookie in a given request
func (s *CookieStore) GetCSRF(req *http.Request) (*http.Cookie, error) {
	return req.Cookie(s.CSRFCookieName)
}

// ClearSession clears the session cookie from a request
func (s *CookieStore) ClearSession(rw http.ResponseWriter, req *http.Request) {
	http.SetCookie(rw, s.makeSessionCookie(req, "", time.Hour*-1, time.Now()))
}

func (s *CookieStore) setSessionCookie(rw http.ResponseWriter, req *http.Request, val string) {
	http.SetCookie(rw, s.makeSessionCookie(req, val, s.CookieExpire, time.Now()))
}

// LoadSession returns a SessionState from the cookie in the request.
func (s *CookieStore) LoadSession(req *http.Request) (*SessionState, error) {
	c, err := req.Cookie(s.Name)
	if err != nil {
		// always http.ErrNoCookie
		return nil, err
	}
	session, err := UnmarshalSession(c.Value, s.CookieCipher)
	if err != nil {
		return nil, ErrInvalidSession
	}
	return session, nil
}

// SaveSession saves a session state to a request sessions.
func (s *CookieStore) SaveSession(rw http.ResponseWriter, req *http.Request, sessionState *SessionState) error {
	value, err := MarshalSession(sessionState, s.CookieCipher)
	if err != nil {
		return err
	}

	s.setSessionCookie(rw, req, value)
	return nil
}
