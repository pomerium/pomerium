// Package proxy is a pomerium service that provides reverse proxying of
// internal routes. The proxy packages interoperates with other pomerium
// services over RPC in order to make access control decisions about a
// given incoming request.
package proxy

import (
	"crypto/cipher"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"html/template"
	stdlog "log"
	"net/http"
	stdhttputil "net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/frontend"
	"github.com/pomerium/pomerium/internal/grpc"
	"github.com/pomerium/pomerium/internal/grpc/authorize/client"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/sessions/cookie"
	"github.com/pomerium/pomerium/internal/sessions/header"
	"github.com/pomerium/pomerium/internal/sessions/queryparam"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/tripper"
	"github.com/pomerium/pomerium/internal/urlutil"
)

const (
	// authenticate urls
	dashboardURL = "/.pomerium"
	signinURL    = "/.pomerium/sign_in"
	signoutURL   = "/.pomerium/sign_out"
	refreshURL   = "/.pomerium/refresh"
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

	authenticateURL        *url.URL
	authenticateSigninURL  *url.URL
	authenticateSignoutURL *url.URL
	authenticateRefreshURL *url.URL

	authorizeURL *url.URL

	AuthorizeClient client.Authorizer

	encoder                encoding.Unmarshaler
	cookieOptions          *cookie.Options
	cookieSecret           []byte
	defaultUpstreamTimeout time.Duration
	refreshCooldown        time.Duration
	Handler                http.Handler
	sessionStore           sessions.SessionStore
	sessionLoaders         []sessions.SessionLoader
	templates              *template.Template
	jwtClaimHeaders        []string
}

// New takes a Proxy service from options and a validation function.
// Function returns an error if options fail to validate.
func New(opts config.Options) (*Proxy, error) {
	if err := ValidateOptions(opts); err != nil {
		return nil, err
	}

	// shared secret is used to encrypt and sign data shared between services
	sharedCipher, _ := cryptutil.NewAEADCipherFromBase64(opts.SharedKey)
	decodedSharedSecret, _ := base64.StdEncoding.DecodeString(opts.SharedKey)
	encoder, err := jws.NewHS256Signer(decodedSharedSecret, opts.AuthenticateURL.Host)
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
		SharedKey:              opts.SharedKey,
		sharedCipher:           sharedCipher,
		encoder:                encoder,
		cookieOptions:          cookieOptions,
		cookieSecret:           decodedSharedSecret,
		defaultUpstreamTimeout: opts.DefaultUpstreamTimeout,
		refreshCooldown:        opts.RefreshCooldown,
		sessionStore:           cookieStore,
		sessionLoaders: []sessions.SessionLoader{
			cookieStore,
			header.NewStore(encoder, "Pomerium"),
			queryparam.NewStore(encoder, "pomerium_session")},
		templates:       template.Must(frontend.NewTemplates()),
		jwtClaimHeaders: opts.JWTClaimsHeaders,
	}
	// errors checked in ValidateOptions
	p.authorizeURL, _ = urlutil.DeepCopy(opts.AuthorizeURL)
	p.authenticateURL, _ = urlutil.DeepCopy(opts.AuthenticateURL)
	p.authenticateSigninURL = p.authenticateURL.ResolveReference(&url.URL{Path: signinURL})
	p.authenticateSignoutURL = p.authenticateURL.ResolveReference(&url.URL{Path: signoutURL})
	p.authenticateRefreshURL = p.authenticateURL.ResolveReference(&url.URL{Path: refreshURL})

	if err := p.UpdatePolicies(&opts); err != nil {
		return nil, err
	}
	metrics.AddPolicyCountCallback("proxy", func() int64 {
		return int64(len(opts.Policies))
	})

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

	p.AuthorizeClient, err = client.New(authzConn)
	return p, err
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
		r = p.reverseProxyHandler(r, policy)

	}
	p.Handler = r
	return nil
}

func (p *Proxy) reverseProxyHandler(r *mux.Router, policy config.Policy) *mux.Router {
	// 1. Create the reverse proxy connection
	proxy := stdhttputil.NewSingleHostReverseProxy(policy.Destination)
	// 2. Create a sublogger to handle any error logs
	sublogger := log.With().Str("route", policy.String()).Logger()
	proxy.ErrorLog = stdlog.New(&log.StdLogWrapper{Logger: &sublogger}, "", 0)
	// 3. Rewrite host headers and add X-Forwarded-Host header
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		req.Header.Add(httputil.HeaderForwardedHost, req.Host)
		director(req)
		if !policy.PreserveHostHeader {
			req.Host = policy.Destination.Host
		}
	}

	// 4. Override any custom transport settings (e.g. TLS settings, etc)
	proxy.Transport = p.roundTripperFromPolicy(&policy)
	// 5. Create a sub-router with a matcher derived from the policy (host, path, etc...)
	rp := r.MatcherFunc(routeMatcherFuncFromPolicy(policy)).Subrouter()
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

	// Optional: if additional headers are to be set for this url
	if len(policy.SetRequestHeaders) != 0 {
		log.Warn().Interface("headers", policy.SetRequestHeaders).Msg("proxy: set request headers")
		rp.Use(SetResponseHeaders(policy.SetRequestHeaders))
	}

	// Optional: if a public route, skip access control middleware
	if policy.AllowPublicUnauthenticatedAccess {
		log.Warn().Str("route", policy.String()).Msg("proxy: all access control disabled")
		return r
	}

	// 4. Retrieve the user session and add it to the request context
	rp.Use(sessions.RetrieveSession(p.sessionLoaders...))
	// 5. AuthN - Verify user session has been added to the request context
	rp.Use(p.AuthenticateSession)
	// 6. AuthZ - Verify the user is authorized for route
	rp.Use(p.AuthorizeSession)
	// 7. Strip the user session cookie from the downstream request
	rp.Use(middleware.StripCookie(p.cookieOptions.Name))
	// 8 . Add claim details to the request logger context and headers
	rp.Use(p.jwtClaimMiddleware(false))

	return r
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

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.Handler.ServeHTTP(w, r)
}

// routeMatcherFuncFromPolicy returns a mux matcher function which compares an http request with a policy.
//
// Routes can be filtered by the `source`, `prefix`, `path` and `regex` fields in the policy config.
func routeMatcherFuncFromPolicy(policy config.Policy) mux.MatcherFunc {
	// match by source
	sourceMatches := func(r *http.Request) bool {
		return r.Host == policy.Source.Host
	}

	// match by prefix
	prefixMatches := func(r *http.Request) bool {
		return policy.Prefix == "" ||
			strings.HasPrefix(r.URL.Path, policy.Prefix)
	}

	// match by path
	pathMatches := func(r *http.Request) bool {
		return policy.Path == "" ||
			r.URL.Path == policy.Path
	}

	// match by path regex
	var regexMatches func(*http.Request) bool
	if policy.Regex == "" {
		regexMatches = func(r *http.Request) bool { return true }
	} else if re, err := regexp.Compile(policy.Regex); err == nil {
		regexMatches = func(r *http.Request) bool {
			return re.MatchString(r.URL.Path)
		}
	} else {
		log.Error().Err(err).Str("regex", policy.Regex).Msg("proxy: invalid regex in policy, ignoring route")
		regexMatches = func(r *http.Request) bool { return false }
	}

	return func(r *http.Request, rm *mux.RouteMatch) bool {
		return sourceMatches(r) && prefixMatches(r) && pathMatches(r) && regexMatches(r)
	}
}
