// Package cache provides a remote cache based implementation of session store
// and loader. See pomerium's cache service for more details.
package cache // import "github.com/pomerium/pomerium/internal/sessions/cache"

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/grpc/cache/client"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
)

var _ sessions.SessionStore = &Store{}
var _ sessions.SessionLoader = &Store{}

// Store implements the session store interface using a cache service.
type Store struct {
	cache        client.Cacher
	encoder      encoding.MarshalUnmarshaler
	queryParam   string
	wrappedStore sessions.SessionStore
}

// Options represent cache store's available configurations.
type Options struct {
	Cache        client.Cacher
	Encoder      encoding.MarshalUnmarshaler
	QueryParam   string
	WrappedStore sessions.SessionStore
}

var defaultOptions = &Options{
	QueryParam: "cache_store_key",
}

// NewStore creates a new cache
func NewStore(o *Options) *Store {
	if o.QueryParam == "" {
		o.QueryParam = defaultOptions.QueryParam
	}
	return &Store{
		cache:        o.Cache,
		encoder:      o.Encoder,
		queryParam:   o.QueryParam,
		wrappedStore: o.WrappedStore,
	}
}

// LoadSession looks for a preset query parameter in the request body
//  representing the key to lookup from the cache.
func (s *Store) LoadSession(r *http.Request) (*sessions.State, string, error) {
	// look for our cache's key in the default query param
	sessionID := r.URL.Query().Get(s.queryParam)
	if sessionID == "" {
		return nil, "", sessions.ErrNoSessionFound
	}
	exists, val, err := s.cache.Get(r.Context(), sessionID)
	if err != nil {
		log.FromRequest(r).Debug().Msg("sessions/cache: miss, trying wrapped loader")
		return nil, "", err
	}
	if !exists {
		return nil, "", sessions.ErrNoSessionFound
	}
	var session sessions.State
	if err := s.encoder.Unmarshal(val, &session); err != nil {
		log.FromRequest(r).Error().Err(err).Msg("sessions/cache: unmarshal")
		return nil, "", sessions.ErrMalformed
	}
	return &session, string(val), nil
}

// ClearSession clears the session from the wrapped store.
func (s *Store) ClearSession(w http.ResponseWriter, r *http.Request) {
	s.wrappedStore.ClearSession(w, r)
}

// SaveSession saves the session to the cache, and wrapped store.
func (s *Store) SaveSession(w http.ResponseWriter, r *http.Request, x interface{}) error {
	err := s.wrappedStore.SaveSession(w, r, x)
	if err != nil {
		return fmt.Errorf("sessions/cache: wrapped store save error %w", err)
	}

	state, ok := x.(*sessions.State)
	if !ok {
		return errors.New("sessions/cache: cannot cache non state type")
	}

	data, err := s.encoder.Marshal(&state)
	if err != nil {
		return fmt.Errorf("sessions/cache: marshal %w", err)
	}

	return s.cache.Set(r.Context(), state.AccessTokenID, data)
}
