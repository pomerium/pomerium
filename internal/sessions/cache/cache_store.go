package cache // import "github.com/pomerium/pomerium/internal/sessions/cache"

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/golang/groupcache"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/urlutil"
)

var _ sessions.SessionStore = &Store{}
var _ sessions.SessionLoader = &Store{}

const (
	defaultQueryParamKey = "ati"
)

// Store implements the session store interface using a distributed cache.
type Store struct {
	name      string
	sharedKey string
	encoder   encoding.MarshalUnmarshaler

	cache        *groupcache.Group
	wrappedStore sessions.SessionStore
}

// defaultCacheSize is ~10MB
var defaultCacheSize int64 = 10 << 20

// NewStore creates a new session store built on the distributed caching library
// groupcache. On a cache miss, the cache store attempts to fallback to another
// SessionStore implementation.
func NewStore(enc encoding.MarshalUnmarshaler, wrappedStore sessions.SessionStore, name, sharedKey string) *Store {
	s := &Store{
		name:         name,
		sharedKey:    sharedKey,
		encoder:      enc,
		wrappedStore: wrappedStore,
	}
	s.cache = groupcache.NewGroup(name, defaultCacheSize, s)
	return s
}

// Get implements groupcache.GetterFunc and returns the session by key,
// populating dest.
func (s *Store) Get(ctx context.Context, id string, dest groupcache.Sink) error {
	// fill the cache with session set as part of the request
	// context set previously as part of SaveSession.
	b := fromContext(ctx)
	if len(b) == 0 {
		return fmt.Errorf("sessions/cache: empty ctx for id: %s", id)
	}
	if err := dest.SetBytes(b); err != nil {
		return fmt.Errorf("sessions/cache: sink error %w", err)
	}
	return nil
}

// LoadSession implements SessionLoaders's LoadSession method for cache store.
func (s *Store) LoadSession(r *http.Request) (*sessions.State, error) {
	// look for our cache's key in the default query param
	sessionID := r.URL.Query().Get(defaultQueryParamKey)
	if sessionID == "" {
		// if unset, fallback to default cache store
		log.FromRequest(r).Debug().Msg("sessions/cache: no query param, trying wrapped loader")
		return s.wrappedStore.LoadSession(r)
	}
	var b []byte
	if err := s.cache.Get(r.Context(), sessionID, groupcache.AllocatingByteSliceSink(&b)); err != nil {
		log.FromRequest(r).Debug().Err(err).Msg("sessions/cache: miss, trying wrapped loader")
		return s.wrappedStore.LoadSession(r)
	}
	var session sessions.State
	if err := s.encoder.Unmarshal(b, &session); err != nil {
		log.FromRequest(r).Error().Err(err).Msg("sessions/cache: unmarshal")
		return nil, sessions.ErrMalformed
	}
	return &session, nil
}

// ClearSession implements SessionStore's ClearSession for the cache store.
// Since group cache has no explicit eviction, we just call the wrapped
// store's ClearSession method here.
func (s *Store) ClearSession(w http.ResponseWriter, r *http.Request) {
	s.wrappedStore.ClearSession(w, r)
}

// SaveSession implements SessionStore's SaveSession method for cache store.
func (s *Store) SaveSession(w http.ResponseWriter, r *http.Request, x interface{}) error {
	err := s.wrappedStore.SaveSession(w, r, x)
	if err != nil {
		return fmt.Errorf("sessions/cache: wrapped store save error %w", err)
	}

	state, ok := x.(*sessions.State)
	if !ok {
		return errors.New("internal/sessions: cannot cache non state type")
	}

	data, err := s.encoder.Marshal(&state)
	if err != nil {
		return fmt.Errorf("sessions/cache: marshal %w", err)
	}

	ctx := newContext(r.Context(), data)
	var b []byte
	return s.cache.Get(ctx, state.AccessTokenID, groupcache.AllocatingByteSliceSink(&b))
}

// AddSessionToCtx is a wrapper function that allows us to add a session
// into http client's round trip and sign the outgoing request.
func (s *Store) AddSessionToCtx(ctx context.Context) http.RoundTripper {
	var sh signedSession
	sh.session = string(fromContext(ctx))
	sh.sharedKey = s.sharedKey
	return sh
}

type signedSession struct {
	session   string
	sharedKey string
}

// RoundTrip copys the request's session context and adds it to the
// outgoing client request as a query param. The whole URL is then signed for
// authenticity.
func (s signedSession) RoundTrip(req *http.Request) (*http.Response, error) {
	// clone request before mutating
	// https://golang.org/src/net/http/client.go?s=4306:5535#L105
	newReq := cloneRequest(req)
	session := s.session
	newReqURL := *newReq.URL
	q := newReqURL.Query()
	q.Set(defaultQueryParamKey, session)
	newReqURL.RawQuery = q.Encode()
	newReq.URL = urlutil.NewSignedURL(s.sharedKey, &newReqURL).Sign()
	return http.DefaultTransport.RoundTrip(newReq)
}

// QueryParamToCtx takes a value from a query param and adds it to the
// current request request context.
func QueryParamToCtx(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := r.FormValue(defaultQueryParamKey)
		ctx := newContext(r.Context(), []byte(session))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

var sessionCtxKey = &contextKey{"PomeriumCachedSessionBytes"}

type contextKey struct {
	name string
}

func newContext(ctx context.Context, b []byte) context.Context {
	ctx = context.WithValue(ctx, sessionCtxKey, b)
	return ctx
}

func fromContext(ctx context.Context) []byte {
	b, _ := ctx.Value(sessionCtxKey).([]byte)
	return b
}

func cloneRequest(req *http.Request) *http.Request {
	r := new(http.Request)
	*r = *req
	r.Header = cloneHeaders(req.Header)
	return r
}

func cloneHeaders(in http.Header) http.Header {
	out := make(http.Header, len(in))
	for key, values := range in {
		newValues := make([]string, len(values))
		copy(newValues, values)
		out[key] = newValues
	}
	return out
}
