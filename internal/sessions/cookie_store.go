package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/log"
)

// ErrInvalidSession is an error for invalid sessions.
var ErrInvalidSession = errors.New("internal/sessions: invalid session")

// ChunkedCanaryByte is the byte value used as a canary prefix to distinguish if
// the cookie is multi-part or not. This constant *should not* be valid
// base64. It's important this byte is ASCII to avoid UTF-8 variable sized runes.
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Directives
const ChunkedCanaryByte byte = '%'

// MaxChunkSize sets the upper bound on a cookie chunks payload value.
// Note, this should be lower than the actual cookie's max size (4096 bytes)
// which includes metadata.
const MaxChunkSize = 3800

// MaxNumChunks limits the number of chunks to iterate through. Conservatively
// set to prevent any abuse.
const MaxNumChunks = 5

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
	domain := req.Host

	if name == s.csrfName() {
		domain = req.Host
	} else if s.CookieDomain != "" {
		domain = s.CookieDomain
	} else {
		domain = splitDomain(domain)
	}

	if h, _, err := net.SplitHostPort(domain); err == nil {
		domain = h
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

func (s *CookieStore) SetCookie(w http.ResponseWriter, cookie *http.Cookie) {
	if len(cookie.String()) <= MaxChunkSize {
		http.SetCookie(w, cookie)
	} else {
		chunks := chunk(cookie.Value, MaxChunkSize)
		for i, c := range chunks {
			// start with a copy of our original cookie
			nc := *cookie
			if i == 0 {
				// if this is the first cookie, add our canary byte
				nc.Value = fmt.Sprintf("%s%s", string(ChunkedCanaryByte), c)
			} else {
				// subsequent parts will be postfixed with their part number
				nc.Name = fmt.Sprintf("%s_%d", cookie.Name, i)
				nc.Value = fmt.Sprintf("%s", c)
			}
			log.Info().Interface("new cookie", nc).Msg("SetCookie: chunked")
			http.SetCookie(w, &nc)
		}
	}

}

func chunk(s string, size int) []string {
	ss := make([]string, 0, len(s)/size+1)
	for len(s) > 0 {
		if len(s) < size {
			size = len(s)
		}
		ss, s = append(ss, s[:size]), s[size:]
	}
	return ss
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
	s.SetCookie(w, s.makeSessionCookie(req, val, s.CookieExpire, time.Now()))
}

// LoadSession returns a SessionState from the cookie in the request.
func (s *CookieStore) LoadSession(req *http.Request) (*SessionState, error) {
	c, err := req.Cookie(s.Name)
	if err != nil {
		return nil, err // http.ErrNoCookie
	}
	cipherText := c.Value

	// if the first byte is our canary byte, we need to handle the multipart bit
	if []byte(c.Value)[0] == ChunkedCanaryByte {
		var b strings.Builder
		fmt.Fprintf(&b, "%s", cipherText[1:])
		for i := 1; i < MaxNumChunks; i++ {
			next, err := req.Cookie(fmt.Sprintf("%s_%d", s.Name, i))
			if err != nil {
				break // break if we can't find the next cookie
			}
			fmt.Fprintf(&b, "%s", next.Value)
		}
		cipherText = b.String()
	}
	session, err := UnmarshalSession(cipherText, s.CookieCipher)
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
