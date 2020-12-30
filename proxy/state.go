package proxy

import (
	"crypto/cipher"
	"encoding/base64"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/internal/sessions/header"
	"github.com/pomerium/pomerium/internal/sessions/queryparam"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

type proxyState struct {
	sharedKey    string
	sharedCipher cipher.AEAD

	authenticateURL          *url.URL
	authenticateDashboardURL *url.URL
	authenticateSigninURL    *url.URL
	authenticateSignoutURL   *url.URL
	authenticateRefreshURL   *url.URL

	encoder         encoding.MarshalUnmarshaler
	cookieSecret    []byte
	refreshCooldown time.Duration
	sessionStore    sessions.SessionStore
	sessionLoaders  []sessions.SessionLoader
	jwtClaimHeaders []string
}

func newProxyStateFromConfig(cfg *config.Config) (*proxyState, error) {
	err := ValidateOptions(cfg.Options)
	if err != nil {
		return nil, err
	}

	state := new(proxyState)
	state.sharedKey = cfg.Options.SharedKey
	state.sharedCipher, _ = cryptutil.NewAEADCipherFromBase64(cfg.Options.SharedKey)
	state.cookieSecret, _ = base64.StdEncoding.DecodeString(cfg.Options.CookieSecret)

	// used to load and verify JWT tokens signed by the authenticate service
	state.encoder, err = jws.NewHS256Signer([]byte(cfg.Options.SharedKey), cfg.Options.GetAuthenticateURL().Host)
	if err != nil {
		return nil, err
	}

	state.refreshCooldown = cfg.Options.RefreshCooldown
	state.jwtClaimHeaders = cfg.Options.JWTClaimsHeaders

	// errors checked in ValidateOptions
	state.authenticateURL, _ = urlutil.DeepCopy(cfg.Options.AuthenticateURL)
	state.authenticateDashboardURL = state.authenticateURL.ResolveReference(&url.URL{Path: dashboardPath})
	state.authenticateSigninURL = state.authenticateURL.ResolveReference(&url.URL{Path: signinURL})
	state.authenticateSignoutURL = state.authenticateURL.ResolveReference(&url.URL{Path: signoutURL})
	state.authenticateRefreshURL = state.authenticateURL.ResolveReference(&url.URL{Path: refreshURL})

	state.sessionStore, err = cookie.NewStore(func() cookie.Options {
		return cookie.Options{
			Name:     cfg.Options.CookieName,
			Domain:   cfg.Options.CookieDomain,
			Secure:   cfg.Options.CookieSecure,
			HTTPOnly: cfg.Options.CookieHTTPOnly,
			Expire:   cfg.Options.CookieExpire,
		}
	}, state.encoder)
	if err != nil {
		return nil, err
	}
	state.sessionLoaders = []sessions.SessionLoader{
		state.sessionStore,
		header.NewStore(state.encoder, httputil.AuthorizationTypePomerium),
		queryparam.NewStore(state.encoder, "pomerium_session"),
	}

	return state, nil
}

type atomicProxyState struct {
	value atomic.Value
}

func newAtomicProxyState(state *proxyState) *atomicProxyState {
	aps := new(atomicProxyState)
	aps.Store(state)
	return aps
}

func (aps *atomicProxyState) Load() *proxyState {
	return aps.value.Load().(*proxyState)
}

func (aps *atomicProxyState) Store(state *proxyState) {
	aps.value.Store(state)
}
