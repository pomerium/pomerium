package cookie // import "github.com/pomerium/pomerium/internal/sessions/cookie"

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/sessions"
)

var _ sessions.SessionStore = &Store{}
var _ sessions.SessionLoader = &Store{}

// timeNow is time.Now but pulled out as a variable for tests.
var timeNow = time.Now

const (
	// ChunkedCanaryByte is the byte value used as a canary prefix to distinguish if
	// the cookie is multi-part or not. This constant *should not* be valid
	// base64. It's important this byte is ASCII to avoid UTF-8 variable sized runes.
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#Directives
	ChunkedCanaryByte byte = '%'
	// MaxChunkSize sets the upper bound on a cookie chunks payload value.
	// Note, this should be lower than the actual cookie's max size (4096 bytes)
	// which includes metadata.
	MaxChunkSize = 3800
	// MaxNumChunks limits the number of chunks to iterate through. Conservatively
	// set to prevent any abuse.
	MaxNumChunks = 5
)

// Store implements the session store interface for session cookies.
type Store struct {
	Name     string
	Domain   string
	Expire   time.Duration
	HTTPOnly bool
	Secure   bool

	encoder encoding.Marshaler
	decoder encoding.Unmarshaler
}

// Options holds options for Store
type Options struct {
	Name     string
	Domain   string
	Expire   time.Duration
	HTTPOnly bool
	Secure   bool
}

// NewStore returns a new session with ciphers for each of the cookie secrets
func NewStore(opts *Options, encoder encoding.MarshalUnmarshaler) (sessions.SessionStore, error) {
	cs, err := NewCookieLoader(opts, encoder)
	if err != nil {
		return nil, err
	}
	cs.encoder = encoder
	return cs, nil
}

// NewCookieLoader returns a new session with ciphers for each of the cookie secrets
func NewCookieLoader(opts *Options, dencoder encoding.Unmarshaler) (*Store, error) {
	if dencoder == nil {
		return nil, fmt.Errorf("internal/sessions: dencoder cannot be nil")
	}
	cs, err := newStore(opts)
	if err != nil {
		return nil, err
	}
	cs.decoder = dencoder
	return cs, nil
}

func newStore(opts *Options) (*Store, error) {
	if opts.Name == "" {
		return nil, fmt.Errorf("internal/sessions: cookie name cannot be empty")
	}

	return &Store{
		Name:     opts.Name,
		Secure:   opts.Secure,
		HTTPOnly: opts.HTTPOnly,
		Domain:   opts.Domain,
		Expire:   opts.Expire,
	}, nil
}

func (cs *Store) makeCookie(value string) *http.Cookie {
	return &http.Cookie{
		Name:     cs.Name,
		Value:    value,
		Path:     "/",
		Domain:   cs.Domain,
		HttpOnly: cs.HTTPOnly,
		Secure:   cs.Secure,
		Expires:  timeNow().Add(cs.Expire),
	}
}

// ClearSession clears the session cookie from a request
func (cs *Store) ClearSession(w http.ResponseWriter, r *http.Request) {
	c := cs.makeCookie("")
	c.MaxAge = -1
	c.Expires = timeNow().Add(-time.Hour)
	http.SetCookie(w, c)
}

func getCookies(r *http.Request, name string) []*http.Cookie {
	allCookies := r.Cookies()
	matchedCookies := make([]*http.Cookie, 0, len(allCookies))
	for _, c := range allCookies {
		if strings.EqualFold(c.Name, name) {
			matchedCookies = append(matchedCookies, c)
		}
	}
	return matchedCookies
}

// LoadSession returns a State from the cookie in the request.
func (cs *Store) LoadSession(r *http.Request) (*sessions.State, error) {
	cookies := getCookies(r, cs.Name)
	if len(cookies) == 0 {
		return nil, sessions.ErrNoSessionFound
	}
	for _, cookie := range cookies {
		data := loadChunkedCookie(r, cookie)

		session := &sessions.State{}
		err := cs.decoder.Unmarshal([]byte(data), session)
		if err == nil {
			return session, nil
		}
	}
	return nil, sessions.ErrMalformed
}

// SaveSession saves a session state to a request's cookie store.
func (cs *Store) SaveSession(w http.ResponseWriter, _ *http.Request, x interface{}) error {
	var value string
	// if cs.encoder != nil {
	// 	data, err := cs.encoder.Marshal(x)
	// 	if err != nil {
	// 		return err
	// 	}
	// 	value = string(data)
	// } else {
	switch v := x.(type) {
	case []byte:
		value = string(v)
	case string:
		value = v
	default:
		if cs.encoder == nil {
			return errors.New("internal/sessions: cannot save non-string type")
		}
		data, err := cs.encoder.Marshal(x)
		if err != nil {
			return err
		}
		value = string(data)
	}

	cs.setSessionCookie(w, value)
	return nil
}

func (cs *Store) setSessionCookie(w http.ResponseWriter, val string) {
	cs.setCookie(w, cs.makeCookie(val))
}

func (cs *Store) setCookie(w http.ResponseWriter, cookie *http.Cookie) {
	if len(cookie.String()) <= MaxChunkSize {
		http.SetCookie(w, cookie)
		return
	}
	for i, c := range chunk(cookie.Value, MaxChunkSize) {
		// start with a copy of our original cookie
		nc := *cookie
		if i == 0 {
			// if this is the first cookie, add our canary byte
			nc.Value = fmt.Sprintf("%s%s", string(ChunkedCanaryByte), c)
		} else {
			// subsequent parts will be postfixed with their part number
			nc.Name = fmt.Sprintf("%s_%d", cookie.Name, i)
			nc.Value = c
		}
		http.SetCookie(w, &nc)
	}
}

func loadChunkedCookie(r *http.Request, c *http.Cookie) string {
	if len(c.Value) == 0 {
		return ""
	}
	if []byte(c.Value)[0] != ChunkedCanaryByte {
		return c.Value
	}

	data := c.Value
	// if the first byte is our canary byte, we need to handle the multipart bit
	var b strings.Builder
	fmt.Fprintf(&b, "%s", data[1:])
	for i := 1; i <= MaxNumChunks; i++ {
		next, err := r.Cookie(fmt.Sprintf("%s_%d", c.Name, i))
		if err != nil {
			break // break if we can't find the next cookie
		}
		fmt.Fprintf(&b, "%s", next.Value)
	}
	data = b.String()

	return data
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
