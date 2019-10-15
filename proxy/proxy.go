package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/mux"
	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/templates"
	"github.com/pomerium/pomerium/internal/tripper"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/proxy/clients"
)

const (
	// dashboardURL	is the path to authenticate's sign in endpoint
	dashboardURL = "/.pomerium"
	// signinURL is the path to authenticate's sign in endpoint
	signinURL = "/.pomerium/sign_in"
	// signoutURL is the path to authenticate's sign out endpoint
	signoutURL = "/.pomerium/sign_out"

	callbackQueryParam = "pomerium-auth-callback"
)

// ValidateOptions checks that proper configuration settings are set to create
// a proper Proxy instance
func ValidateOptions(o config.Options) error {
	if _, err := cryptutil.NewAEADCipherFromBase64(o.SharedKey); err != nil {
		return fmt.Errorf("proxy: invalid 'SHARED_SECRET': %v", err)
	}

	if _, err := cryptutil.NewAEADCipherFromBase64(o.CookieSecret); err != nil {
		return fmt.Errorf("proxy: invalid 'COOKIE_SECRET': %v", err)
	}

	if err := urlutil.ValidateURL(o.AuthenticateURL); err != nil {
		return fmt.Errorf("proxy: invalid 'AUTHENTICATE_SERVICE_URL': %v", err)
	}

	if err := urlutil.ValidateURL(o.AuthorizeURL); err != nil {
		return fmt.Errorf("proxy: invalid 'AUTHORIZE_SERVICE_URL': %v", err)
	}

	if len(o.SigningKey) != 0 {
		if _, err := cryptutil.NewES256Signer(o.SigningKey, ""); err != nil {
			return fmt.Errorf("proxy: invalid 'SIGNING_KEY': %v", err)
		}
	}
	return nil
}

// Proxy stores all the information associated with proxying a request.
type Proxy struct {
	// SharedKey used to mutually authenticate service communication
	SharedKey              string
	authenticateURL        *url.URL
	authenticateSigninURL  *url.URL
	authenticateSignoutURL *url.URL
	authorizeURL           *url.URL

	AuthorizeClient clients.Authorizer

	encoder                cryptutil.SecureEncoder
	cookieName             string
	cookieDomain           string
	cookieSecret           []byte
	defaultUpstreamTimeout time.Duration
	refreshCooldown        time.Duration
	Handler                http.Handler
	sessionStore           sessions.SessionStore
	sessionLoaders         []sessions.SessionLoader
	signingKey             string
	templates              *template.Template
}

// New takes a Proxy service from options and a validation function.
// Function returns an error if options fail to validate.
func New(opts config.Options) (*Proxy, error) {
	if err := ValidateOptions(opts); err != nil {
		return nil, err
	}

	// errors checked in ValidateOptions
	decodedCookieSecret, _ := base64.StdEncoding.DecodeString(opts.CookieSecret)
	cipher, _ := cryptutil.NewAEADCipherFromBase64(opts.CookieSecret)

	encoder := cryptutil.NewSecureJSONEncoder(cipher)

	if opts.CookieDomain == "" {
		opts.CookieDomain = sessions.ParentSubdomain(opts.AuthenticateURL.String())
	}

	cookieStore, err := sessions.NewCookieStore(
		&sessions.CookieStoreOptions{
			Name:           opts.CookieName,
			CookieDomain:   opts.CookieDomain,
			CookieSecure:   opts.CookieSecure,
			CookieHTTPOnly: opts.CookieHTTPOnly,
			CookieExpire:   opts.CookieExpire,
			Encoder:        encoder,
		})

	if err != nil {
		return nil, err
	}
	p := &Proxy{
		SharedKey: opts.SharedKey,

		encoder:                encoder,
		cookieSecret:           decodedCookieSecret,
		cookieDomain:           opts.CookieDomain,
		cookieName:             opts.CookieName,
		defaultUpstreamTimeout: opts.DefaultUpstreamTimeout,
		refreshCooldown:        opts.RefreshCooldown,
		sessionStore:           cookieStore,
		sessionLoaders: []sessions.SessionLoader{
			cookieStore,
			sessions.NewHeaderStore(encoder),
			sessions.NewQueryParamStore(encoder)},
		signingKey: opts.SigningKey,
		templates:  templates.New(),
	}
	// errors checked in ValidateOptions
	p.authorizeURL, _ = urlutil.DeepCopy(opts.AuthorizeURL)
	p.authenticateURL, _ = urlutil.DeepCopy(opts.AuthenticateURL)

	p.authenticateSigninURL = p.authenticateURL.ResolveReference(&url.URL{Path: signinURL})
	p.authenticateSignoutURL = p.authenticateURL.ResolveReference(&url.URL{Path: signoutURL})

	if err := p.UpdatePolicies(&opts); err != nil {
		return nil, err
	}
	metrics.AddPolicyCountCallback("proxy", func() int64 {
		return int64(len(opts.Policies))
	})
	p.AuthorizeClient, err = clients.NewAuthorizeClient("grpc",
		&clients.Options{
			Addr:                    p.authorizeURL,
			OverrideCertificateName: opts.OverrideCertificateName,
			SharedSecret:            opts.SharedKey,
			CA:                      opts.CA,
			CAFile:                  opts.CAFile,
			RequestTimeout:          opts.GRPCClientTimeout,
			ClientDNSRoundRobin:     opts.GRPCClientDNSRoundRobin,
			WithInsecure:            opts.GRPCInsecure,
		})
	return p, err
}

// UpdateOptions updates internal structures based on config.Options
func (p *Proxy) UpdateOptions(o config.Options) error {
	if p == nil {
		return nil
	}
	log.Info().Msg("proxy: updating options")
	return p.UpdatePolicies(&o)
}

// UpdatePolicies updates the H basedon the configured policies
func (p *Proxy) UpdatePolicies(opts *config.Options) error {
	var err error
	if len(opts.Policies) == 0 {
		log.Warn().Msg("proxy: configuration has no policies")
	}
	r := httputil.NewRouter()
	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httputil.ErrorResponse(w, r, httputil.Error(fmt.Sprintf("%s route unknown", r.Host), http.StatusNotFound, nil))
	})
	r.SkipClean(true)
	r.StrictSlash(true)
	r.HandleFunc("/robots.txt", p.RobotsTxt).Methods(http.MethodGet)
	// dashboard handlers are registered to all routes
	r = p.registerDashboardHandlers(r)

	if opts.ForwardAuthURL != nil {
		// if a forward auth endpoint is set, register its handlers
		h := r.Host(opts.ForwardAuthURL.Host).Subrouter()
		h.PathPrefix("/").Handler(p.registerFwdAuthHandlers())
	}

	for _, policy := range opts.Policies {
		if err := policy.Validate(); err != nil {
			return fmt.Errorf("proxy: invalid policy %s", err)
		}
		r, err = p.reverseProxyHandler(r, &policy)
		if err != nil {
			return err
		}
	}
	p.Handler = r
	return nil
}

func (p *Proxy) reverseProxyHandler(r *mux.Router, policy *config.Policy) (*mux.Router, error) {
	// 1. Create the reverse proxy connection
	proxy := httputil.NewReverseProxy(policy.Destination)
	// 2. Override any custom transport settings (e.g. TLS settings, etc)
	proxy.Transport = p.roundTripperFromPolicy(policy)
	// 3. Create a sub-router for a given route's hostname (`httpbin.corp.example.com`)
	rp := r.Host(policy.Source.Host).Subrouter()
	rp.PathPrefix("/").Handler(proxy)

	// Optional: If websockets are enabled, do not set a handler request timeout
	// websockets cannot use the non-hijackable timeout-handler
	if !policy.AllowWebsockets {
		timeout := p.defaultUpstreamTimeout
		if policy.UpstreamTimeout != 0 {
			timeout = policy.UpstreamTimeout
		}
		timeoutMsg := fmt.Sprintf("%s timed out in %s", policy.Destination.Host, timeout)
		rp.Use(middleware.TimeoutHandlerFunc(timeout, timeoutMsg))
	}

	// Optional: a cors preflight check, skip access control middleware
	if policy.CORSAllowPreflight {
		log.Warn().Str("route", policy.String()).Msg("proxy: cors preflight enabled")
		rp.Use(middleware.CorsBypass(proxy))
	}

	// Optional: if a public route, skip access control middleware
	if policy.AllowPublicUnauthenticatedAccess {
		log.Warn().Str("route", policy.String()).Msg("proxy: all access control disabled")
		return r, nil
	}

	// 4. Retrieve the user session and add it to the request context
	rp.Use(sessions.RetrieveSession(p.sessionLoaders...))
	// 5. Strip the user session cookie from the downstream request
	rp.Use(middleware.StripCookie(p.cookieName))
	// 6. AuthN - Verify the user is authenticated. Set email, group, & id headers
	rp.Use(p.AuthenticateSession)
	// 7. AuthZ - Verify the user is authorized for route
	rp.Use(p.AuthorizeSession)
	// Optional: Add a signed JWT attesting to the user's id, email, and group
	if len(p.signingKey) != 0 {
		signer, err := cryptutil.NewES256Signer(p.signingKey, policy.Source.Host)
		if err != nil {
			return nil, err
		}
		rp.Use(p.SignRequest(signer))
	}
	// Optional: if additional headers are to be set for this url
	if len(policy.SetRequestHeaders) != 0 {
		log.Warn().Interface("headers", policy.SetRequestHeaders).Msg("proxy: set request headers")
		rp.Use(SetResponseHeaders(policy.SetRequestHeaders))
	}
	return r, nil
}

// roundTripperFromPolicy adjusts the std library's `DefaultTransport RoundTripper`
// for a given route. A route's `RoundTripper` establishes network connections
// as needed and caches them for reuse by subsequent calls.
func (p *Proxy) roundTripperFromPolicy(policy *config.Policy) http.RoundTripper {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	c := tripper.NewChain()
	c = c.Append(metrics.HTTPMetricsRoundTripper("proxy", policy.Destination.Host))

	var tlsClientConfig tls.Config
	var isCustomClientConfig bool

	if policy.TLSSkipVerify {
		tlsClientConfig.InsecureSkipVerify = true
		isCustomClientConfig = true
		log.Warn().Str("policy", policy.String()).Msg("proxy: tls skip verify")
	}

	if policy.RootCAs != nil {
		tlsClientConfig.RootCAs = policy.RootCAs
		isCustomClientConfig = true
		log.Debug().Str("policy", policy.String()).Msg("proxy: custom root ca")
	}

	if policy.ClientCertificate != nil {
		tlsClientConfig.Certificates = []tls.Certificate{*policy.ClientCertificate}
		isCustomClientConfig = true
		log.Debug().Str("policy", policy.String()).Msg("proxy: client certs enabled")
	}

	if policy.TLSServerName != "" {
		tlsClientConfig.ServerName = policy.TLSServerName
		isCustomClientConfig = true
		log.Debug().Str("policy", policy.String()).Msgf("proxy: tls override hostname: %s", policy.TLSServerName)
	}

	// We avoid setting a custom client config unless we have to as
	// if TLSClientConfig is nil, the default configuration is used.
	if isCustomClientConfig {
		transport.TLSClientConfig = &tlsClientConfig
	}
	return c.Then(transport)
}
