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

// RetrieveSession takes a slice of session loaders and tries to find a valid
// session in the order they were supplied and is added to the request's context
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

// retrieveFromRequest extracts sessions state from the request by calling
// token find functions in the order they where provided.
func retrieveFromRequest(r *http.Request, sessions ...SessionLoader) (*State, error) {
	for _, s := range sessions {
		state, err := s.LoadSession(r)
		if err != nil && !errors.Is(err, ErrNoSessionFound) {
			return state, err
		}
		if state != nil {
			err := state.Verify(r.Host)
			return state, err // N.B.: state is _not nil_
		}
	}

	return nil, ErrNoSessionFound
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
