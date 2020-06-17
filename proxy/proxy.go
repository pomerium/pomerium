// Package proxy is a pomerium service that provides reverse proxying of
// internal routes. The proxy packages interoperates with other pomerium
// services over RPC in order to make access control decisions about a
// given incoming request.
package proxy

import (
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/gorilla/mux"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/frontend"
	"github.com/pomerium/pomerium/internal/grpc"
	"github.com/pomerium/pomerium/internal/grpc/databroker"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/internal/sessions/header"
	"github.com/pomerium/pomerium/internal/sessions/queryparam"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/urlutil"
)

const (
	// authenticate urls
	dashboardPath = "/.pomerium"
	signinURL     = "/.pomerium/sign_in"
	signoutURL    = "/.pomerium/sign_out"
	refreshURL    = "/.pomerium/refresh"
)

// ValidateOptions checks that proper configuration settings are set to create
// a proper Proxy instance
func ValidateOptions(o config.Options) error {
	if _, err := cryptutil.NewAEADCipherFromBase64(o.SharedKey); err != nil {
		return fmt.Errorf("proxy: invalid 'SHARED_SECRET': %w", err)
	}

	if _, err := cryptutil.NewAEADCipherFromBase64(o.CookieSecret); err != nil {
		return fmt.Errorf("proxy: invalid 'COOKIE_SECRET': %w", err)
	}

	if err := urlutil.ValidateURL(o.AuthenticateURL); err != nil {
		return fmt.Errorf("proxy: invalid 'AUTHENTICATE_SERVICE_URL': %w", err)
	}

	if err := urlutil.ValidateURL(o.AuthorizeURL); err != nil {
		return fmt.Errorf("proxy: invalid 'AUTHORIZE_SERVICE_URL': %w", err)
	}
	return nil
}

// Proxy stores all the information associated with proxying a request.
type Proxy struct {
	// SharedKey used to mutually authenticate service communication
	SharedKey    string
	sharedCipher cipher.AEAD

	authorizeURL             *url.URL
	authenticateURL          *url.URL
	authenticateDashboardURL *url.URL
	authenticateSigninURL    *url.URL
	authenticateSignoutURL   *url.URL
	authenticateRefreshURL   *url.URL

	encoder         encoding.Unmarshaler
	cookieOptions   *cookie.Options
	cookieSecret    []byte
	refreshCooldown time.Duration
	sessionStore    sessions.SessionStore
	sessionLoaders  []sessions.SessionLoader
	templates       *template.Template
	jwtClaimHeaders []string
	authzClient     envoy_service_auth_v2.AuthorizationClient

	dataBrokerClient databroker.DataBrokerServiceClient

	currentRouter atomic.Value
}

// New takes a Proxy service from options and a validation function.
// Function returns an error if options fail to validate.
func New(opts config.Options) (*Proxy, error) {
	if err := ValidateOptions(opts); err != nil {
		return nil, err
	}

	sharedCipher, _ := cryptutil.NewAEADCipherFromBase64(opts.SharedKey)
	decodedCookieSecret, _ := base64.StdEncoding.DecodeString(opts.CookieSecret)

	// used to load and verify JWT tokens signed by the authenticate service
	encoder, err := jws.NewHS256Signer([]byte(opts.SharedKey), opts.GetAuthenticateURL().Host)
	if err != nil {
		return nil, err
	}

	cookieOptions := &cookie.Options{
		Name:     opts.CookieName,
		Domain:   opts.CookieDomain,
		Secure:   opts.CookieSecure,
		HTTPOnly: opts.CookieHTTPOnly,
		Expire:   opts.CookieExpire,
	}

	cookieStore, err := cookie.NewStore(cookieOptions, encoder)
	if err != nil {
		return nil, err
	}

	p := &Proxy{
		SharedKey:    opts.SharedKey,
		sharedCipher: sharedCipher,
		encoder:      encoder,

		cookieSecret:    decodedCookieSecret,
		cookieOptions:   cookieOptions,
		refreshCooldown: opts.RefreshCooldown,
		sessionStore:    cookieStore,
		sessionLoaders: []sessions.SessionLoader{
			cookieStore,
			header.NewStore(encoder, httputil.AuthorizationTypePomerium),
			queryparam.NewStore(encoder, "pomerium_session")},
		templates:       template.Must(frontend.NewTemplates()),
		jwtClaimHeaders: opts.JWTClaimsHeaders,
	}
	p.currentRouter.Store(httputil.NewRouter())
	// errors checked in ValidateOptions
	p.authorizeURL, _ = urlutil.DeepCopy(opts.AuthorizeURL)
	p.authenticateURL, _ = urlutil.DeepCopy(opts.AuthenticateURL)
	p.authenticateDashboardURL = p.authenticateURL.ResolveReference(&url.URL{Path: dashboardPath})
	p.authenticateSigninURL = p.authenticateURL.ResolveReference(&url.URL{Path: signinURL})
	p.authenticateSignoutURL = p.authenticateURL.ResolveReference(&url.URL{Path: signoutURL})
	p.authenticateRefreshURL = p.authenticateURL.ResolveReference(&url.URL{Path: refreshURL})

	authzConn, err := grpc.NewGRPCClientConn(&grpc.Options{
		Addr:                    p.authorizeURL,
		OverrideCertificateName: opts.OverrideCertificateName,
		CA:                      opts.CA,
		CAFile:                  opts.CAFile,
		RequestTimeout:          opts.GRPCClientTimeout,
		ClientDNSRoundRobin:     opts.GRPCClientDNSRoundRobin,
		WithInsecure:            opts.GRPCInsecure,
	})
	if err != nil {
		return nil, err
	}
	p.authzClient = envoy_service_auth_v2.NewAuthorizationClient(authzConn)

	cacheConn, err := grpc.NewGRPCClientConn(&grpc.Options{
		Addr:                    opts.DataBrokerURL,
		OverrideCertificateName: opts.OverrideCertificateName,
		CA:                      opts.CA,
		CAFile:                  opts.CAFile,
		RequestTimeout:          opts.GRPCClientTimeout,
		ClientDNSRoundRobin:     opts.GRPCClientDNSRoundRobin,
		WithInsecure:            opts.GRPCInsecure,
	})
	if err != nil {
		return nil, err
	}
	p.dataBrokerClient = databroker.NewDataBrokerServiceClient(cacheConn)

	if err := p.UpdatePolicies(&opts); err != nil {
		return nil, err
	}
	metrics.AddPolicyCountCallback("pomerium-proxy", func() int64 {
		return int64(len(opts.Policies))
	})

	return p, nil
}

// UpdateOptions implements the OptionsUpdater interface and updates internal
// structures based on config.Options
func (p *Proxy) UpdateOptions(o config.Options) error {
	if p == nil {
		return nil
	}
	log.Info().Str("checksum", fmt.Sprintf("%x", o.Checksum())).Msg("proxy: updating options")
	return p.UpdatePolicies(&o)
}

// UpdatePolicies updates the H basedon the configured policies
func (p *Proxy) UpdatePolicies(opts *config.Options) error {
	if len(opts.Policies) == 0 {
		log.Warn().Msg("proxy: configuration has no policies")
	}
	r := httputil.NewRouter()
	r.NotFoundHandler = httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return httputil.NewError(http.StatusNotFound, fmt.Errorf("%s route unknown", r.Host))
	})
	r.SkipClean(true)
	r.StrictSlash(true)
	r.HandleFunc("/robots.txt", p.RobotsTxt).Methods(http.MethodGet)
	// dashboard handlers are registered to all routes
	r = p.registerDashboardHandlers(r)

	if opts.ForwardAuthURL != nil {
		// if a forward auth endpoint is set, register its handlers
		h := r.Host(opts.ForwardAuthURL.Hostname()).Subrouter()
		h.PathPrefix("/").Handler(p.registerFwdAuthHandlers())
	}

	for _, policy := range opts.Policies {
		if err := policy.Validate(); err != nil {
			return fmt.Errorf("proxy: invalid policy %w", err)
		}
	}

	p.currentRouter.Store(r)

	return nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.currentRouter.Load().(*mux.Router).ServeHTTP(w, r)
}
