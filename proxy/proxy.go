package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	stdlog "log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/metrics"
	"github.com/pomerium/pomerium/internal/policy"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/templates"
	"github.com/pomerium/pomerium/internal/tripper"
	"github.com/pomerium/pomerium/proxy/clients"
)

const (
	// HeaderJWT is the header key containing JWT signed user details.
	HeaderJWT = "x-pomerium-jwt-assertion"
	// HeaderUserID is the header key containing the user's id.
	HeaderUserID = "x-pomerium-authenticated-user-id"
	// HeaderEmail is the header key containing the user's email.
	HeaderEmail = "x-pomerium-authenticated-user-email"
	// HeaderGroups is the header key containing the user's groups.
	HeaderGroups = "x-pomerium-authenticated-user-groups"
)

// ValidateOptions checks that proper configuration settings are set to create
// a proper Proxy instance
func ValidateOptions(o config.Options) error {
	decoded, err := base64.StdEncoding.DecodeString(o.SharedKey)
	if err != nil {
		return fmt.Errorf("`SHARED_SECRET` setting is invalid base64: %v", err)
	}
	if len(decoded) != 32 {
		return fmt.Errorf("`SHARED_SECRET` want 32 but got %d bytes", len(decoded))
	}
	if len(o.Policies) == 0 {
		return errors.New("missing setting: no policies defined")
	}
	if o.AuthenticateURL.String() == "" {
		return errors.New("missing setting: authenticate-service-url")
	}
	if o.AuthenticateURL.Scheme != "https" {
		return errors.New("authenticate-service-url must be a valid https url")
	}
	if o.AuthorizeURL.String() == "" {
		return errors.New("missing setting: authorize-service-url")
	}
	if o.AuthorizeURL.Scheme != "https" {
		return errors.New("authorize-service-url must be a valid https url")
	}
	if o.CookieSecret == "" {
		return errors.New("missing setting: cookie-secret")
	}
	decodedCookieSecret, err := base64.StdEncoding.DecodeString(o.CookieSecret)
	if err != nil {
		return fmt.Errorf("cookie secret is invalid base64: %v", err)
	}
	if len(decodedCookieSecret) != 32 {
		return fmt.Errorf("cookie secret expects 32 bytes but got %d", len(decodedCookieSecret))
	}
	if len(o.SigningKey) != 0 {
		_, err := base64.StdEncoding.DecodeString(o.SigningKey)
		if err != nil {
			return fmt.Errorf("signing key is invalid base64: %v", err)
		}
	}
	return nil
}

// Proxy stores all the information associated with proxying a request.
type Proxy struct {
	SharedKey string

	// authenticate service
	AuthenticateURL    *url.URL
	AuthenticateClient clients.Authenticator

	// authorize service
	AuthorizeClient clients.Authorizer

	// session
	cipher       cryptutil.Cipher
	csrfStore    sessions.CSRFStore
	sessionStore sessions.SessionStore
	restStore    sessions.SessionStore

	redirectURL     *url.URL
	templates       *template.Template
	routeConfigs    map[string]*routeConfig
	refreshCooldown time.Duration
}

type routeConfig struct {
	mux    http.Handler
	policy policy.Policy
}

// New takes a Proxy service from options and a validation function.
// Function returns an error if options fail to validate.
func New(opts config.Options) (*Proxy, error) {
	if err := ValidateOptions(opts); err != nil {
		return nil, err
	}
	// error explicitly handled by validate
	decodedSecret, _ := base64.StdEncoding.DecodeString(opts.CookieSecret)
	cipher, err := cryptutil.NewCipher(decodedSecret)
	if err != nil {
		return nil, fmt.Errorf("cookie-secret error: %s", err.Error())
	}

	cookieStore, err := sessions.NewCookieStore(
		&sessions.CookieStoreOptions{
			Name:           opts.CookieName,
			CookieDomain:   opts.CookieDomain,
			CookieSecure:   opts.CookieSecure,
			CookieHTTPOnly: opts.CookieHTTPOnly,
			CookieExpire:   opts.CookieExpire,
			CookieCipher:   cipher,
		})

	if err != nil {
		return nil, err
	}
	restStore, err := sessions.NewRestStore(&sessions.RestStoreOptions{Cipher: cipher})
	if err != nil {
		return nil, err
	}
	p := &Proxy{
		routeConfigs: make(map[string]*routeConfig),
		// services
		AuthenticateURL: &opts.AuthenticateURL,
		// session state
		cipher:          cipher,
		csrfStore:       cookieStore,
		sessionStore:    cookieStore,
		restStore:       restStore,
		SharedKey:       opts.SharedKey,
		redirectURL:     &url.URL{Path: "/.pomerium/callback"},
		templates:       templates.New(),
		refreshCooldown: opts.RefreshCooldown,
	}

	err = p.UpdatePolicies(opts)
	if err != nil {
		return nil, err
	}

	p.AuthenticateClient, err = clients.NewAuthenticateClient("grpc",
		&clients.Options{
			Addr:                    opts.AuthenticateURL.Host,
			InternalAddr:            opts.AuthenticateInternalAddr.Host,
			OverrideCertificateName: opts.OverrideCertificateName,
			SharedSecret:            opts.SharedKey,
			CA:                      opts.CA,
			CAFile:                  opts.CAFile,
		})
	if err != nil {
		return nil, err
	}
	p.AuthorizeClient, err = clients.NewAuthorizeClient("grpc",
		&clients.Options{
			Addr:                    opts.AuthorizeURL.Host,
			OverrideCertificateName: opts.OverrideCertificateName,
			SharedSecret:            opts.SharedKey,
			CA:                      opts.CA,
			CAFile:                  opts.CAFile,
		})
	return p, err
}

// UpdatePolicies updates the handlers based on the configured policies
func (p *Proxy) UpdatePolicies(opts config.Options) error {
	routeConfigs := make(map[string]*routeConfig)
	for _, route := range opts.Policies {
		proxy := NewReverseProxy(route.Destination)
		handler, err := NewReverseProxyHandler(opts, proxy, &route)
		if err != nil {
			return err
		}
		routeConfigs[route.Source.Host] = &routeConfig{
			mux:    handler,
			policy: route,
		}
		log.Info().Str("src", route.Source.Host).Str("dst", route.Destination.Host).Msg("proxy: new route")
	}
	p.routeConfigs = routeConfigs
	return nil
}

// UpstreamProxy stores information for proxying the request to the upstream.
type UpstreamProxy struct {
	name       string
	cookieName string
	handler    http.Handler
	signer     cryptutil.JWTSigner
}

// deleteUpstreamCookies deletes the session cookie from the request header string.
func deleteUpstreamCookies(req *http.Request, cookieName string) {
	headers := []string{}
	for _, cookie := range req.Cookies() {
		if cookie.Name != cookieName {
			headers = append(headers, cookie.String())
		}
	}
	req.Header.Set("Cookie", strings.Join(headers, ";"))
}

func (u *UpstreamProxy) signRequest(r *http.Request) {
	if u.signer != nil {
		jwt, err := u.signer.SignJWT(
			r.Header.Get(HeaderUserID),
			r.Header.Get(HeaderEmail),
			r.Header.Get(HeaderGroups))
		if err == nil {
			r.Header.Set(HeaderJWT, jwt)
		}
	}
}

// ServeHTTP signs the http request and deletes cookie headers
// before calling the upstream's ServeHTTP function.
func (u *UpstreamProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	deleteUpstreamCookies(r, u.cookieName)
	u.signRequest(r)
	u.handler.ServeHTTP(w, r)
}

// NewReverseProxy returns a new ReverseProxy that routes URLs to the scheme, host, and
// base path provided in target. NewReverseProxy rewrites the Host header.
func NewReverseProxy(to *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(to)
	sublogger := log.With().Str("proxy", to.Host).Logger()
	proxy.ErrorLog = stdlog.New(&log.StdLogWrapper{Logger: &sublogger}, "", 0)
	// todo(bdd): default is already http.DefaultTransport)
	// proxy.Transport = defaultUpstreamTransport
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		// Identifies the originating IP addresses of a client connecting to
		// a web server through an HTTP proxy or a load balancer.
		req.Header.Add("X-Forwarded-Host", req.Host)
		director(req)
		req.Host = to.Host
	}

	chain := tripper.NewChain().Append(metrics.HTTPMetricsRoundTripper("proxy"))
	proxy.Transport = chain.Then(nil)
	return proxy
}

// NewReverseProxyHandler applies handler specific options to a given route.
func NewReverseProxyHandler(o config.Options, proxy *httputil.ReverseProxy, route *policy.Policy) (http.Handler, error) {
	up := &UpstreamProxy{
		name:       route.Destination.Host,
		handler:    proxy,
		cookieName: o.CookieName,
	}
	if len(o.SigningKey) != 0 {
		decodedSigningKey, _ := base64.StdEncoding.DecodeString(o.SigningKey)
		signer, err := cryptutil.NewES256Signer(decodedSigningKey, route.Source.Host)
		if err != nil {
			return nil, err
		}
		up.signer = signer
	}
	timeout := o.DefaultUpstreamTimeout
	if route.UpstreamTimeout != 0 {
		timeout = route.UpstreamTimeout
	}
	timeoutMsg := fmt.Sprintf("%s failed to respond within the %s timeout period", route.Destination.Host, timeout)
	timeoutHandler := http.TimeoutHandler(up, timeout, timeoutMsg)
	return websocketHandlerFunc(up, timeoutHandler, o), nil
}

// urlParse wraps url.Parse to add a scheme if none-exists.
// https://github.com/golang/go/issues/12585
func urlParse(uri string) (*url.URL, error) {
	if !strings.Contains(uri, "://") {
		uri = fmt.Sprintf("https://%s", uri)
	}
	return url.ParseRequestURI(uri)
}

// UpdateOptions updates internal structures based on config.Options
func (p *Proxy) UpdateOptions(o config.Options) error {
	log.Info().Msg("proxy: updating options")
	err := p.UpdatePolicies(o)
	if err != nil {
		return fmt.Errorf("Could not update policies: %s", err)
	}
	return nil
}
