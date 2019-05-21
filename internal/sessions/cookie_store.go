package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
)

// ErrInvalidSession is an error for invalid sessions.
var ErrInvalidSession = errors.New("internal/sessions: invalid session")

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
	Name           string
	CookieCipher   cryptutil.Cipher
	CookieExpire   time.Duration
	CookieRefresh  time.Duration
	CookieSecure   bool
	CookieHTTPOnly bool
	CookieDomain   string
}

// CookieStoreOptions holds options for CookieStore
type CookieStoreOptions struct {
	Name           string
	CookieSecure   bool
	CookieHTTPOnly bool
	CookieDomain   string
	CookieExpire   time.Duration
	CookieCipher   cryptutil.Cipher
}

// NewCookieStore returns a new session with ciphers for each of the cookie secrets
func NewCookieStore(opts *CookieStoreOptions) (*CookieStore, error) {
	if opts.Name == "" {
		return nil, fmt.Errorf("internal/sessions: cookie name cannot be empty")
	}
	if opts.CookieCipher == nil {
		return nil, fmt.Errorf("internal/sessions: cipher cannot be nil")
	}
	return &CookieStore{
		Name:           opts.Name,
		CookieSecure:   opts.CookieSecure,
		CookieHTTPOnly: opts.CookieHTTPOnly,
		CookieDomain:   opts.CookieDomain,
		CookieExpire:   opts.CookieExpire,
		CookieCipher:   opts.CookieCipher,
	}, nil
}

func (s *CookieStore) makeCookie(req *http.Request, name string, value string, expiration time.Duration, now time.Time) *http.Cookie {
	// if csrf, scope cookie to the route or service specific domain
	domain := req.Host
	if h, _, err := net.SplitHostPort(domain); err == nil {
		domain = h
	}
	if s.CookieDomain != "" {
		domain = s.CookieDomain
	}

	// Non-CSRF sessions can shared, and set domain-wide
	if !strings.Contains(name, "csrf") {
		domain = splitDomain(domain)
	}

	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		HttpOnly: s.CookieHTTPOnly,
		Secure:   s.CookieSecure,
	}
	// only set an expiration if we want one, otherwise default to non perm session based
	if expiration != 0 {
		c.Expires = now.Add(expiration)
	}
	return c
}

func (s *CookieStore) csrfName() string {
	return fmt.Sprintf("%s_csrf", s.Name)
}

// makeSessionCookie constructs a session cookie given the request, an expiration time and the current time.
func (s *CookieStore) makeSessionCookie(req *http.Request, value string, expiration time.Duration, now time.Time) *http.Cookie {
	return s.makeCookie(req, s.Name, value, expiration, now)
}

// makeCSRFCookie creates a CSRF cookie given the request, an expiration time, and the current time.
// CSRF cookies should be scoped to the actual domain
func (s *CookieStore) makeCSRFCookie(req *http.Request, value string, expiration time.Duration, now time.Time) *http.Cookie {
	return s.makeCookie(req, s.csrfName(), value, expiration, now)
}

// ClearCSRF clears the CSRF cookie from the request
func (s *CookieStore) ClearCSRF(w http.ResponseWriter, req *http.Request) {
	http.SetCookie(w, s.makeCSRFCookie(req, "", time.Hour*-1, time.Now()))
}

// SetCSRF sets the CSRFCookie creates a CSRF cookie in a given request
func (s *CookieStore) SetCSRF(w http.ResponseWriter, req *http.Request, val string) {
	http.SetCookie(w, s.makeCSRFCookie(req, val, s.CookieExpire, time.Now()))
}

// GetCSRF gets the CSRFCookie creates a CSRF cookie in a given request
func (s *CookieStore) GetCSRF(req *http.Request) (*http.Cookie, error) {
	return req.Cookie(s.csrfName())
}

// ClearSession clears the session cookie from a request
func (s *CookieStore) ClearSession(w http.ResponseWriter, req *http.Request) {
	http.SetCookie(w, s.makeSessionCookie(req, "", time.Hour*-1, time.Now()))
}

func (s *CookieStore) setSessionCookie(w http.ResponseWriter, req *http.Request, val string) {
	http.SetCookie(w, s.makeSessionCookie(req, val, s.CookieExpire, time.Now()))
}

// LoadSession returns a SessionState from the cookie in the request.
func (s *CookieStore) LoadSession(req *http.Request) (*SessionState, error) {
	c, err := req.Cookie(s.Name)
	if err != nil {
		return nil, err // http.ErrNoCookie
	}
	session, err := UnmarshalSession(c.Value, s.CookieCipher)
	if err != nil {
		return nil, ErrInvalidSession
	}
	return session, nil
}

// SaveSession saves a session state to a request sessions.
func (s *CookieStore) SaveSession(w http.ResponseWriter, req *http.Request, sessionState *SessionState) error {
	value, err := MarshalSession(sessionState, s.CookieCipher)
	if err != nil {
		return err
	}
	s.setSessionCookie(w, req, value)
	return nil
}

func splitDomain(s string) string {
	if strings.Count(s, ".") < 2 {
		return ""
	}
	split := strings.SplitN(s, ".", 2)
	return split[1]
}
