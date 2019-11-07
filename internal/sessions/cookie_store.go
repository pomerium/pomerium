package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

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

// CookieStore implements the session store interface for session cookies.
type CookieStore struct {
	Name     string
	Domain   string
	Expire   time.Duration
	HTTPOnly bool
	Secure   bool
	encoder  Marshaler
	decoder  Unmarshaler
}

// CookieOptions holds options for CookieStore
type CookieOptions struct {
	Name     string
	Domain   string
	Expire   time.Duration
	HTTPOnly bool
	Secure   bool
}

// NewCookieStore returns a new session with ciphers for each of the cookie secrets
func NewCookieStore(opts *CookieOptions, encoder Encoder) (*CookieStore, error) {
	if opts.Name == "" {
		return nil, fmt.Errorf("internal/sessions: cookie name cannot be empty")
	}
	if encoder == nil {
		return nil, fmt.Errorf("internal/sessions: decoder cannot be nil")
	}
	return &CookieStore{
		Name:     opts.Name,
		Secure:   opts.Secure,
		HTTPOnly: opts.HTTPOnly,
		Domain:   opts.Domain,
		Expire:   opts.Expire,
		encoder:  encoder,
		decoder:  encoder,
	}, nil
}

// NewCookieLoader returns a new session with ciphers for each of the cookie secrets
func NewCookieLoader(opts *CookieOptions, decoder Unmarshaler) (*CookieStore, error) {
	if opts.Name == "" {
		return nil, fmt.Errorf("internal/sessions: cookie name cannot be empty")
	}
	if decoder == nil {
		return nil, fmt.Errorf("internal/sessions: decoder cannot be nil")
	}
	return &CookieStore{
		Name:     opts.Name,
		Secure:   opts.Secure,
		HTTPOnly: opts.HTTPOnly,
		Domain:   opts.Domain,
		Expire:   opts.Expire,
		decoder:  decoder,
	}, nil
}

func (cs *CookieStore) makeCookie(req *http.Request, name string, value string, expiration time.Duration, now time.Time) *http.Cookie {
	domain := req.Host

	if cs.Domain != "" {
		domain = cs.Domain
	}

	if h, _, err := net.SplitHostPort(domain); err == nil {
		domain = h
	}
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   domain,
		HttpOnly: cs.HTTPOnly,
		Secure:   cs.Secure,
	}
	// only set an expiration if we want one, otherwise default to non perm session based
	if expiration != 0 {
		c.Expires = now.Add(expiration)
	}
	return c
}

// ClearSession clears the session cookie from a request
func (cs *CookieStore) ClearSession(w http.ResponseWriter, req *http.Request) {
	http.SetCookie(w, cs.makeCookie(req, cs.Name, "", time.Hour*-1, time.Now()))
}

// LoadSession returns a State from the cookie in the request.
func (cs *CookieStore) LoadSession(req *http.Request) (*State, error) {
	data := loadChunkedCookie(req, cs.Name)
	if data == "" {
		return nil, ErrNoSessionFound
	}
	var session State
	err := cs.decoder.Unmarshal([]byte(data), &session)
	if err != nil {
		return nil, ErrMalformed
	}

	return &session, err
}

// SaveSession saves a session state to a request's cookie store.
func (cs *CookieStore) SaveSession(w http.ResponseWriter, req *http.Request, x interface{}) error {
	var value string
	if cs.encoder != nil {
		data, err := cs.encoder.Marshal(x)
		if err != nil {
			return err
		}
		value = string(data)
	} else {
		switch v := x.(type) {
		case []byte:
			value = string(v)
		case string:
			value = v
		default:
			return errors.New("internal/sessions: cannot save non-string type")
		}
	}
	cs.setSessionCookie(w, req, value)
	return nil
}

// makeSessionCookie constructs a session cookie given the request, an expiration time and the current time.
func (cs *CookieStore) makeSessionCookie(req *http.Request, value string, expiration time.Duration, now time.Time) *http.Cookie {
	return cs.makeCookie(req, cs.Name, value, expiration, now)
}

func (cs *CookieStore) setSessionCookie(w http.ResponseWriter, req *http.Request, val string) {
	cs.setCookie(w, cs.makeSessionCookie(req, val, cs.Expire, time.Now()))
}

func (cs *CookieStore) setCookie(w http.ResponseWriter, cookie *http.Cookie) {
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

func loadChunkedCookie(r *http.Request, cookieName string) string {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	data := c.Value
	// if the first byte is our canary byte, we need to handle the multipart bit
	if []byte(c.Value)[0] == ChunkedCanaryByte {
		var b strings.Builder
		fmt.Fprintf(&b, "%s", data[1:])
		for i := 1; i <= MaxNumChunks; i++ {
			next, err := r.Cookie(fmt.Sprintf("%s_%d", cookieName, i))
			if err != nil {
				break // break if we can't find the next cookie
			}
			fmt.Fprintf(&b, "%s", next.Value)
		}
		data = b.String()
	}
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
