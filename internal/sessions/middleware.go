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
			jwt, err := retrieveFromRequest(r, s...)
			ctx = NewContext(ctx, jwt, err)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(hfn)
	}
}

// retrieveFromRequest extracts sessions state from the request by calling
// token find functions in the order they where provided.
func retrieveFromRequest(r *http.Request, sessions ...SessionLoader) (string, error) {
	for _, s := range sessions {
		jwt, err := s.LoadSession(r)
		if err != nil && !errors.Is(err, ErrNoSessionFound) {
			return "", err
		} else if err == nil {
			return jwt, nil
		}
	}

	return "", ErrNoSessionFound
}

// NewContext sets context values for the user session state and error.
func NewContext(ctx context.Context, jwt string, err error) context.Context {
	ctx = context.WithValue(ctx, SessionCtxKey, jwt)
	ctx = context.WithValue(ctx, ErrorCtxKey, err)
	return ctx
}

// FromContext retrieves context values for the user session state and error.
func FromContext(ctx context.Context) (string, error) {
	jwt, _ := ctx.Value(SessionCtxKey).(string)
	err, _ := ctx.Value(ErrorCtxKey).(error)
	return jwt, err
}

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation. This technique
// for defining context keys was copied from Go 1.7's new use of context in net/http.
type contextKey struct {
	name string
}
