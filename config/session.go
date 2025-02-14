package config

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/internal/sessions/header"
	"github.com/pomerium/pomerium/internal/sessions/queryparam"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

// A SessionStore saves and loads sessions based on the options.
type SessionStore struct {
	store   sessions.SessionStore
	loader  sessions.SessionLoader
	options *Options
	encoder encoding.MarshalUnmarshaler
}

var _ sessions.SessionStore = (*SessionStore)(nil)

// NewSessionStore creates a new SessionStore from the Options.
func NewSessionStore(options *Options) (*SessionStore, error) {
	store := &SessionStore{
		options: options,
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
func (store *SessionStore) LoadSessionStateAndCheckIDP(r *http.Request) (*sessions.State, error) {
	state, err := store.LoadSessionState(r)
	if err != nil {
		return nil, err
	}

	// confirm that the identity provider id matches the state
	if state.IdentityProviderID != "" {
		idp, err := store.options.GetIdentityProviderForRequestURL(urlutil.GetAbsoluteURL(r).String())
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

// An IDPTokenSessionHandler handles incoming idp access and identity tokens.
type IDPTokenSessionHandler struct {
	options    *Options
	getSession func(ctx context.Context, id string) (*session.Session, error)
	putSession func(ctx context.Context, s *session.Session) error
}

// NewIDPTokenSessionHandler creates a new IDPTokenSessionHandler.
func NewIDPTokenSessionHandler(
	options *Options,
	getSession func(ctx context.Context, id string) (*session.Session, error),
	putSession func(ctx context.Context, s *session.Session) error,
) *IDPTokenSessionHandler {
	return &IDPTokenSessionHandler{
		options:    options,
		getSession: getSession,
		putSession: putSession,
	}
}

// // CreateSessionForIncomingIDPToken creates a session from an incoming idp access or identity token.
// // If no such tokens are found or they are invalid ErrNoSessionFound will be returned.
// func (h *IDPTokenSessionHandler) CreateSessionForIncomingIDPToken(r *http.Request) (*session.Session, error) {
// 	idp, err := h.options.GetIdentityProviderForRequestURL(urlutil.GetAbsoluteURL(r).String())
// 	if err != nil {
// 		return nil, err
// 	}

// 	return nil, sessions.ErrNoSessionFound
// }

// func (h *IDPTokenSessionHandler) getIncomingIDPAccessToken(r *http.Request) (rawAccessToken string, ok bool) {
// 	if h.options.

// 	return "", false
// }

// func (h *IDPTokenSessionHandler) getIncomingIDPIdentityToken(r *http.Request) (rawIdentityToken string, ok bool) {
// 	return "", false
// }

// func CreateSessionForIncomingIDPToken(
// 	r *http.Request,
// 	options *Options,
// 	policy *Policy,
// 	getSession func(ctx context.Context, id string) (*session.Session, error),
// 	putSession func(ctx context.Context, s *session.Session) error)(*session.Session, error) {
// }

// GetIncomingIDPAccessTokenForPolicy returns the raw idp access token from a request if there is one.
func (options *Options) GetIncomingIDPAccessTokenForPolicy(policy *Policy, r *http.Request) (rawAccessToken string, ok bool) {
	bearerTokenFormat := BearerTokenFormatDefault
	if options != nil && options.BearerTokenFormat != nil {
		bearerTokenFormat = *options.BearerTokenFormat
	}
	if policy != nil && policy.BearerTokenFormat != nil {
		bearerTokenFormat = *policy.BearerTokenFormat
	}

	if token := r.Header.Get("X-Pomerium-IDP-Access-Token"); token != "" {
		return token, true
	}

	if auth := r.Header.Get("Authorization"); auth != "" {
		prefix := "Pomerium-IDP-Access-Token "
		if strings.HasPrefix(strings.ToLower(auth), strings.ToLower(prefix)) {
			return strings.TrimPrefix(auth, prefix), true
		}

		prefix = "Bearer Pomerium-IDP-Access-Token-"
		if strings.HasPrefix(strings.ToLower(auth), strings.ToLower(prefix)) {
			return strings.TrimPrefix(auth, prefix), true
		}

		prefix = "Bearer "
		if strings.HasPrefix(strings.ToLower(auth), strings.ToLower(prefix)) && bearerTokenFormat == BearerTokenFormatIDPAccessToken {
			return strings.TrimPrefix(auth, prefix), true
		}
	}

	return "", false
}

// GetIncomingIDPAccessTokenForPolicy returns the raw idp identity token from a request if there is one.
func (options *Options) GetIncomingIDPIdentityTokenForPolicy(policy *Policy, r *http.Request) (rawIdentityToken string, ok bool) {
	bearerTokenFormat := BearerTokenFormatDefault
	if options != nil && options.BearerTokenFormat != nil {
		bearerTokenFormat = *options.BearerTokenFormat
	}
	if policy != nil && policy.BearerTokenFormat != nil {
		bearerTokenFormat = *policy.BearerTokenFormat
	}

	if token := r.Header.Get("X-Pomerium-IDP-Identity-Token"); token != "" {
		return token, true
	}

	if auth := r.Header.Get("Authorization"); auth != "" {
		prefix := "Pomerium-IDP-Identity-Token "
		if strings.HasPrefix(strings.ToLower(auth), strings.ToLower(prefix)) {
			return strings.TrimPrefix(auth, prefix), true
		}

		prefix = "Bearer Pomerium-IDP-Identity-Token-"
		if strings.HasPrefix(strings.ToLower(auth), strings.ToLower(prefix)) {
			return strings.TrimPrefix(auth, prefix), true
		}

		prefix = "Bearer "
		if strings.HasPrefix(strings.ToLower(auth), strings.ToLower(prefix)) && bearerTokenFormat == BearerTokenFormatIDPIdentityToken {
			return strings.TrimPrefix(auth, prefix), true
		}
	}

	return "", false
}
