package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// Context keys
var (
	SessionCtxKey = &contextKey{"Session"}
	ErrorCtxKey   = &contextKey{"Error"}
)

// Library errors
var (
	ErrExpired        = errors.New("internal/sessions: session is expired")
	ErrNoSessionFound = errors.New("internal/sessions: session is not found")
	ErrMalformed      = errors.New("internal/sessions: session is malformed")
)

// RetrieveSession http middleware handler will verify a auth session from a http request.
//
// RetrieveSession will search for a auth session in a http request, in the order:
//   1. `pomerium_session` URI query parameter
//   2. `Authorization: BEARER` request header
//   3. Cookie `_pomerium` value
func RetrieveSession(s SessionStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return retrieve(s, TokenFromQuery, TokenFromHeader, TokenFromCookie)(next)
	}
}

func retrieve(s SessionStore, findTokenFns ...func(r *http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		hfn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			token, err := retrieveFromRequest(s, r, findTokenFns...)
			ctx = NewContext(ctx, token, err)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(hfn)
	}
}

func retrieveFromRequest(s SessionStore, r *http.Request, findTokenFns ...func(r *http.Request) string) (*State, error) {
	var tokenStr string
	var err error

	// Extract token string from the request by calling token find functions in
	// the order they where provided. Further extraction stops if a function
	// returns a non-empty string.
	for _, fn := range findTokenFns {
		tokenStr = fn(r)
		if tokenStr != "" {
			break
		}
	}
	if tokenStr == "" {
		return nil, ErrNoSessionFound
	}

	state, err := s.LoadSession(r)
	if err != nil {
		return nil, ErrMalformed
	}
	err = state.Valid()
	if err != nil {
		// a little unusual but we want to return the expired state too
		return state, err
	}

	// Valid!
	return state, nil
}

// NewContext sets context values for the user session state and error.
func NewContext(ctx context.Context, t *State, err error) context.Context {
	ctx = context.WithValue(ctx, SessionCtxKey, t)
	ctx = context.WithValue(ctx, ErrorCtxKey, err)
	return ctx
}

// FromContext retrieves context values for the user session state and error.
func FromContext(ctx context.Context) (*State, error) {
	state, _ := ctx.Value(SessionCtxKey).(*State)
	err, _ := ctx.Value(ErrorCtxKey).(error)
	return state, err
}

// TokenFromCookie tries to retrieve the token string from a cookie named
// "_pomerium".
func TokenFromCookie(r *http.Request) string {
	cookie, err := r.Cookie("_pomerium")
	if err != nil {
		return ""
	}
	return cookie.Value
}

// TokenFromHeader tries to retrieve the token string from the
// "Authorization" request header: "Authorization: BEARER T".
func TokenFromHeader(r *http.Request) string {
	// Get token from authorization header.
	bearer := r.Header.Get("Authorization")
	if len(bearer) > 7 && strings.EqualFold(bearer[0:6], "BEARER") {
		return bearer[7:]
	}
	return ""
}

// TokenFromQuery tries to retrieve the token string from the "pomerium_session" URI
// query parameter.
// todo(bdd) : document setting session code as queryparam
func TokenFromQuery(r *http.Request) string {
	// Get token from query param named "pomerium_session".
	return r.URL.Query().Get("pomerium_session")
}

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation. This technique
// for defining context keys was copied from Go 1.7's new use of context in net/http.
type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "SessionStore context value " + k.name
}
