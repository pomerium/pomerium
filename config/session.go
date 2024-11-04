package config

import (
	"fmt"
	"net/http"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/internal/sessions/header"
	"github.com/pomerium/pomerium/internal/sessions/queryparam"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// A SessionStore saves and loads sessions based on the options.
type SessionStore struct {
	store    sessions.SessionStore
	loader   sessions.SessionLoader
	options  *Options
	encoder  encoding.MarshalUnmarshaler
	idpCache *IdentityProviderCache
}

var _ sessions.SessionStore = (*SessionStore)(nil)

// NewSessionStore creates a new SessionStore from the Options.
func NewSessionStore(options *Options, idpCache *IdentityProviderCache) (*SessionStore, error) {
	store := &SessionStore{
		options:  options,
		idpCache: idpCache,
	}

	sharedKey, err := options.GetSharedKey()
	if err != nil {
		return nil, fmt.Errorf("config/sessions: shared_key is required: %w", err)
	}

	store.encoder, err = jws.NewHS256Signer(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("config/sessions: invalid session encoder: %w", err)
	}

	store.store, err = cookie.NewStore(func() cookie.Options {
		return cookie.Options{
			Name:     options.CookieName,
			Domain:   options.CookieDomain,
			Secure:   true,
			HTTPOnly: options.CookieHTTPOnly,
			Expire:   options.CookieExpire,
			SameSite: options.GetCookieSameSite(),
		}
	}, store.encoder)
	if err != nil {
		return nil, err
	}
	headerStore := header.NewStore(store.encoder)
	queryParamStore := queryparam.NewStore(store.encoder, urlutil.QuerySession)
	store.loader = sessions.MultiSessionLoader(store.store, headerStore, queryParamStore)

	return store, nil
}

// ClearSession clears the session.
func (store *SessionStore) ClearSession(w http.ResponseWriter, r *http.Request) {
	store.store.ClearSession(w, r)
}

// LoadSession loads the session.
func (store *SessionStore) LoadSession(r *http.Request) (string, error) {
	return store.loader.LoadSession(r)
}

// LoadSessionState loads the session state from a request.
func (store *SessionStore) LoadSessionState(r *http.Request) (*sessions.State, error) {
	rawJWT, err := store.loader.LoadSession(r)
	if err != nil {
		return nil, err
	}

	var state sessions.State
	err = store.encoder.Unmarshal([]byte(rawJWT), &state)
	if err != nil {
		return nil, err
	}

	return &state, nil
}

// LoadSessionStateAndCheckIDP loads the session state from a request and checks that the idp id matches.
func (store *SessionStore) LoadSessionStateAndCheckIDP(r *http.Request, routeID uint64) (*sessions.State, error) {
	state, err := store.LoadSessionState(r)
	if err != nil {
		return nil, err
	}

	// confirm that the identity provider id matches the state
	if state.IdentityProviderID != "" {
		idp, err := store.idpCache.GetIdentityProviderForRouteID(routeID)
		if err != nil {
			return nil, err
		}

		if idp.GetId() != state.IdentityProviderID {
			return nil, fmt.Errorf("unexpected session state identity provider id: %s != %s",
				idp.GetId(), state.IdentityProviderID)
		}
	}

	return state, nil
}

// SaveSession saves the session.
func (store *SessionStore) SaveSession(w http.ResponseWriter, r *http.Request, v any) error {
	return store.store.SaveSession(w, r, v)
}
