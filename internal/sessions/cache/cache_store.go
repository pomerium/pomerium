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
)

var _ sessions.SessionStore = &Store{}
var _ sessions.SessionLoader = &Store{}

const (
	defaultQueryParamKey = "ati"
)

type Store struct {
	name    string
	encoder encoding.Marshaler
	decoder encoding.Unmarshaler

	cache        *groupcache.Group
	wrappedStore sessions.SessionStore
}

const defaultCacheSize = 20 * (4 << 20)

func NewStore(enc encoding.MarshalUnmarshaler, wrappedStore sessions.SessionStore, name string) *Store {
	store := &Store{
		name:         name,
		encoder:      enc,
		decoder:      enc,
		wrappedStore: wrappedStore,
	}

	store.cache = groupcache.NewGroup(name, defaultCacheSize, groupcache.GetterFunc(
		func(ctx context.Context, id string, dest groupcache.Sink) error {
			// fill the cache with session set as part
			// of the request context in SaveSession.
			b := fromContext(ctx)
			if len(b) == 0 {
				return fmt.Errorf("sessions/cache: no match for key : %s", id)
			}
			if err := dest.SetBytes(b); err != nil {
				return fmt.Errorf("sessions/cache: sink error %w", err)
			}
			return nil
		},
	))

	return store
}

func (s *Store) LoadSession(r *http.Request) (*sessions.State, error) {
	sessionID := r.URL.Query().Get(defaultQueryParamKey)
	if sessionID == "" {
		log.FromRequest(r).Debug().Msg("sessions/cache: no query param, using wrapped loader")
		return s.wrappedStore.LoadSession(r)
	}

	var b []byte
	if err := s.cache.Get(r.Context(), sessionID, groupcache.AllocatingByteSliceSink(&b)); err != nil {
		log.FromRequest(r).Debug().Err(err).Msg("sessions/cache: miss, using wrapped loader")
		return s.wrappedStore.LoadSession(r)
	}
	var session sessions.State
	if err := s.decoder.Unmarshal(b, &session); err != nil {
		log.FromRequest(r).Error().Err(err).Msg("sessions/cache: unmarshal")
		return nil, sessions.ErrMalformed
	}
	return &session, nil

}

func (s *Store) ClearSession(w http.ResponseWriter, r *http.Request) {
	// todo(bdd): do we want to handle eviction? If a refresh token is
	// invalidated by the IdP we'd get an error on refresh and the session
	// would just naturally get evicted as part of the underlying LRU cache
	s.wrappedStore.ClearSession(w, r)
}

func (s *Store) SaveSession(w http.ResponseWriter, r *http.Request, x interface{}) error {
	err := s.wrappedStore.SaveSession(w, r, x)
	if err != nil {
		return fmt.Errorf("sessions/cache: wrapped store save error %w", err)
	}

	//todo(bdd): replace type assertion with interface type that implements a hasher type?
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
	err = s.cache.Get(ctx, state.AccessTokenID, groupcache.AllocatingByteSliceSink(&b))
	if err != nil {
		return fmt.Errorf("sessions/cache: save error %w", err)
	}
	return nil
}

var sessionCtxKey = &contextKey{"PomeriumCachedSessionBytes"}

type contextKey struct {
	name string
}

func (k *contextKey) String() string {
	return "context value " + k.name
}

func newContext(ctx context.Context, b []byte) context.Context {
	ctx = context.WithValue(ctx, sessionCtxKey, b)
	return ctx
}

func fromContext(ctx context.Context) []byte {
	b, _ := ctx.Value(sessionCtxKey).([]byte)
	return b
}
