package config

import (
	"context"
	"fmt"
	"net/http"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/internal/sessions/header"
	"github.com/pomerium/pomerium/internal/sessions/queryparam"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// A SessionStore saves and loads sessions based on the options.
type SessionStore struct {
	options     *Options
	encoder     encoding.MarshalUnmarshaler
	loader      sessions.SessionLoader
	policyCache *PolicyCache
}

// NewSessionStore creates a new SessionStore from the Options.
func NewSessionStore(options *Options) (*SessionStore, error) {
	cache, err := NewPolicyCache(options)
	if err != nil {
		return nil, err
	}
	store := &SessionStore{
		options:     options,
		policyCache: cache,
	}

	sharedKey, err := options.GetSharedKey()
	if err != nil {
		return nil, fmt.Errorf("config/sessions: shared_key is required: %w", err)
	}

	store.encoder, err = jws.NewHS256Signer(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("config/sessions: invalid session encoder: %w", err)
	}

	cookieStore, err := cookie.NewStore(func() cookie.Options {
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
	store.loader = sessions.MultiSessionLoader(cookieStore, headerStore, queryParamStore)

	return store, nil
}

// LoadSessionState loads the session state from a request.
func (store *SessionStore) LoadSessionState(ctx context.Context, r *http.Request) (*sessions.State, error) {
	ctx, span := trace.StartSpan(ctx, "session_store.load_session_state")
	defer span.End()

	rawJWT, err := store.loader.LoadSession(ctx, r)
	if err != nil {
		return nil, err
	}

	var state sessions.State
	err = store.encoder.Unmarshal([]byte(rawJWT), &state)
	if err != nil {
		return nil, err
	}

	// confirm that the identity provider id matches the state
	if state.IdentityProviderID != "" {
		idp, err := store.policyCache.GetIdentityProviderForRequestURL(ctx, store.options, urlutil.GetAbsoluteURL(r).String())
		if err != nil {
			return nil, err
		}

		if idp.GetId() != state.IdentityProviderID {
			return nil, fmt.Errorf("unexpected session state identity provider id: %s != %s",
				idp.GetId(), state.IdentityProviderID)
		}
	}

	return &state, nil
}
