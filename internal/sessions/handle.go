package sessions

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

// ErrSessionHandleNotFound indicates no session was found.
var ErrSessionHandleNotFound = errors.New("session not found")

var ErrSessionHandleMalformed = errors.New("malformed session")

// A SessionHandleReader reads session handles from an http request.
type SessionHandleReader interface {
	ReadSessionHandle(r *http.Request) (*session.Handle, error)
}

type sessionHandleReader struct {
	key        []byte
	cookieName string
}

// NewSessionHandleReader creates a new SessionHandleReader.
func NewSessionHandleReader(
	key []byte,
	cookieName string,
) SessionHandleReader {
	return &sessionHandleReader{
		key:        key,
		cookieName: cookieName,
	}
}

// ReadSessionHandle reads a session handle from the http request.
func (shr *sessionHandleReader) ReadSessionHandle(r *http.Request) (*session.Handle, error) {
	for _, fn := range []func(*http.Request) (string, error){
		shr.readRawJWTFromCookie,
		shr.readRawJWTFromHeader,
		shr.readRawJWTFromQuery,
	} {
		rawJWT, err := fn(r)
		if errors.Is(err, ErrSessionHandleNotFound) {
			continue
		}
		h, err := session.UnmarshalAndVerifyHandle(shr.key, rawJWT)
		if err != nil {
			return nil, ErrSessionHandleMalformed
		}
		return h, nil
	}
	return nil, ErrSessionHandleNotFound
}

func (shr *sessionHandleReader) readRawJWTFromCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(shr.cookieName)
	if err != nil {
		return "", ErrSessionHandleNotFound
	}
	return cookie.Value, nil
}

func (shr *sessionHandleReader) readRawJWTFromHeader(r *http.Request) (string, error) {
	// X-Pomerium-Authorization: <JWT>
	if jwt := r.Header.Get(httputil.HeaderPomeriumAuthorization); jwt != "" {
		return jwt, nil
	}

	bearer := r.Header.Get(httputil.HeaderAuthorization)
	// Authorization: Pomerium <JWT>
	prefix := httputil.AuthorizationTypePomerium + " "
	if strings.HasPrefix(bearer, prefix) {
		return bearer[len(prefix):], nil
	}

	// Authorization: Bearer Pomerium-<JWT>
	prefix = "Bearer " + httputil.AuthorizationTypePomerium + "-"
	if strings.HasPrefix(bearer, prefix) {
		return bearer[len(prefix):], nil
	}

	return "", ErrSessionHandleNotFound
}

func (shr *sessionHandleReader) readRawJWTFromQuery(r *http.Request) (string, error) {
	value := r.URL.Query().Get(urlutil.QuerySession)
	if value != "" {
		return value, nil
	}
	return "", ErrSessionHandleNotFound
}

// A SessionHandleWriter writes session handles to an http response.
type SessionHandleWriter interface {
	WriteSessionHandle(w http.ResponseWriter, h *session.Handle) error
}

type sessionHandleWriter struct {
	key            []byte
	cookieName     string
	cookieDomain   string
	cookieExpiry   time.Duration
	cookieHTTPOnly bool
	cookieSameSite http.SameSite
}

// NewSessionHandleWriter creates a new SessionHandleWriter.
func NewSessionHandleWriter(
	key []byte,
	cookieName string,
	cookieDomain string,
	cookieExpiry time.Duration,
	cookieHTTPOnly bool,
	cookieSameSite http.SameSite,
) SessionHandleWriter {
	return &sessionHandleWriter{
		key:            key,
		cookieName:     cookieName,
		cookieDomain:   cookieDomain,
		cookieExpiry:   cookieExpiry,
		cookieHTTPOnly: cookieHTTPOnly,
		cookieSameSite: cookieSameSite,
	}
}

// WriteSessionHandle writes the session handle to the http response as a cookie.
func (shw *sessionHandleWriter) WriteSessionHandle(w http.ResponseWriter, h *session.Handle) error {
	rawJWT, err := session.MarshalAndSignHandle(shw.key, h)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     shw.cookieName,
		Value:    rawJWT,
		Domain:   shw.cookieDomain,
		Expires:  time.Now().Add(shw.cookieExpiry),
		HttpOnly: shw.cookieHTTPOnly,
		Secure:   true,
		SameSite: shw.cookieSameSite,
	})
	return nil
}
