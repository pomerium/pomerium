// Package forwardauth is a pomerium service that handles forward authentication requests.
package forwardauth

import (
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/gorilla/mux"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/internal/sessions/header"
	"github.com/pomerium/pomerium/internal/sessions/queryparam"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc"
)

const (
	// authenticate urls
	dashboardPath = "/.pomerium"
	signinURL     = "/.pomerium/sign_in"
	signoutURL    = "/.pomerium/sign_out"
	refreshURL    = "/.pomerium/refresh"
)

// ForwardAuth stores all the information associated with proxying a request.
type ForwardAuth struct {
	state          *atomicFaState
	currentOptions *config.AtomicOptions
	currentRouter  atomic.Value
}

// Mount mounts the authenticate routes to the given router.
func (fa *ForwardAuth) Mount(r *mux.Router) {
	r.PathPrefix("/").Handler(fa.registerFwdAuthHandlers())
	fa.currentRouter.Store(r)
}

// New returns new ForwardAuth instance from given config.
func New(cfg *config.Config) (*ForwardAuth, error) {
	state, err := newFaStateFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	p := &ForwardAuth{
		state:          newAtomicFaState(state),
		currentOptions: config.NewAtomicOptions(),
	}
	p.currentRouter.Store(httputil.NewRouter())

	return p, nil
}

type faState struct {
	sharedKey    string
	sharedCipher cipher.AEAD

	authorizeURL             *url.URL
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
	authzClient     envoy_service_auth_v2.AuthorizationClient
}

type atomicFaState struct {
	value atomic.Value
}

func newFaStateFromConfig(cfg *config.Config) (*faState, error) {
	err := validateOptions(cfg.Options)
	if err != nil {
		return nil, err
	}

	state := new(faState)
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

	// errors checked in validateOptions
	state.authorizeURL, _ = urlutil.DeepCopy(cfg.Options.AuthorizeURL)
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
		queryparam.NewStore(state.encoder, "pomerium_session")}

	authzConn, err := grpc.GetGRPCClientConn("authorize", &grpc.Options{
		Addr:                    state.authorizeURL,
		OverrideCertificateName: cfg.Options.OverrideCertificateName,
		CA:                      cfg.Options.CA,
		CAFile:                  cfg.Options.CAFile,
		RequestTimeout:          cfg.Options.GRPCClientTimeout,
		ClientDNSRoundRobin:     cfg.Options.GRPCClientDNSRoundRobin,
		WithInsecure:            cfg.Options.GRPCInsecure,
		ServiceName:             cfg.Options.Services,
	})
	if err != nil {
		return nil, err
	}
	state.authzClient = envoy_service_auth_v2.NewAuthorizationClient(authzConn)

	return state, nil
}

func newAtomicFaState(state *faState) *atomicFaState {
	aps := new(atomicFaState)
	aps.Store(state)
	return aps
}

func (aps *atomicFaState) Load() *faState {
	return aps.value.Load().(*faState)
}

func (aps *atomicFaState) Store(state *faState) {
	aps.value.Store(state)
}

// validateOptions checks that proper configuration settings are set to create
// a proper ForwardAuth instance.
func validateOptions(o *config.Options) error {
	if err := urlutil.ValidateURL(o.ForwardAuthURL); err != nil {
		return fmt.Errorf("proxy: invalid 'FORWARD_AUTH_URL': %w", err)
	}
	if err := urlutil.ValidateURL(o.AuthenticateURL); err != nil {
		return fmt.Errorf("proxy: invalid 'AUTHENTICATE_SERVICE_URL': %w", err)
	}

	if err := urlutil.ValidateURL(o.AuthorizeURL); err != nil {
		return fmt.Errorf("proxy: invalid 'AUTHORIZE_SERVICE_URL': %w", err)
	}
	return nil
}

// OnConfigChange updates internal structures based on config.Options
func (fa *ForwardAuth) OnConfigChange(cfg *config.Config) {
	log.Info().Str("checksum", fmt.Sprintf("%x", cfg.Options.Checksum())).Msg("forwardauth: updating options")
	fa.currentOptions.Store(cfg.Options)

	state, err := newFaStateFromConfig(cfg)
	if err != nil {
		log.Error().Err(err).Msg("proxy: failed to update proxy state from configuration settings")
		return
	}
	fa.state.Store(state)
}

func (fa *ForwardAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fa.currentRouter.Load().(*mux.Router).ServeHTTP(w, r)
}
