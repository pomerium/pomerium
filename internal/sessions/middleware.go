package sessions // import "github.com/pomerium/pomerium/internal/sessions"

import (
	"context"
	"errors"
	"net/http"
)

// Context keys
var (
	SessionCtxKey = &contextKey{"Session"}
	ErrorCtxKey   = &contextKey{"Error"}
)

// RetrieveSession will search for a auth session in a http request, in the order:
//   1. `pomerium_session` URI query parameter
//   2. `Authorization: BEARER` request header
//   3. Cookie `_pomerium` value
func RetrieveSession(s ...SessionLoader) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return retrieve(s...)(next)
	}
}

func retrieve(s ...SessionLoader) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		hfn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			state, err := retrieveFromRequest(r, s...)
			ctx = NewContext(ctx, state, err)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(hfn)
	}
}

func retrieveFromRequest(r *http.Request, sessions ...SessionLoader) (*State, error) {
	state := new(State)
	var err error

	// Extract sessions state from the request by calling token find functions in
	// the order they where provided. Further extraction stops if a function
	// returns a non-empty string.
	for _, s := range sessions {
		state, err = s.LoadSession(r)
		if err != nil && !errors.Is(err, ErrNoSessionFound) {
			//  unexpected error
			return nil, err
		}
		// break, we found a session state
		if state != nil {
			break
		}
	}
	// no session found if state is still empty
	if state == nil {
		return nil, ErrNoSessionFound
	}

	if err = state.Valid(); err != nil {
		// a little unusual but we want to return the expired state too
		return state, err
	}

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

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation. This technique
// for defining context keys was copied from Go 1.7's new use of context in net/http.
type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "context value " + k.name
}
