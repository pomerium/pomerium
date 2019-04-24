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

	"github.com/pomerium/envconfig"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/policy"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/templates"
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

// Options represents the configurations available for the proxy service.
type Options struct {
	Policy     string `envconfig:"POLICY"`
	PolicyFile string `envconfig:"POLICY_FILE"`

	// AuthenticateURL represents the externally accessible http endpoints
	// used for authentication requests and callbacks
	AuthenticateURL *url.URL `envconfig:"AUTHENTICATE_SERVICE_URL"`
	// AuthenticateInternalAddr is used as an override when using a load balancer
	// or ingress that does not natively support routing gRPC.
	AuthenticateInternalAddr string `envconfig:"AUTHENTICATE_INTERNAL_URL"`

	// AuthorizeURL is the routable destination of the authorize service's
	// gRPC endpoint. NOTE: As above, many load balancers do not support
	// externally routed gRPC so this may be an internal location.
	AuthorizeURL *url.URL `envconfig:"AUTHORIZE_SERVICE_URL"`

	// Settings to enable custom behind-the-ingress service communication
	OverrideCertificateName string `envconfig:"OVERRIDE_CERTIFICATE_NAME"`
	CA                      string `envconfig:"CERTIFICATE_AUTHORITY"`
	CAFile                  string `envconfig:"CERTIFICATE_AUTHORITY_FILE"`

	// SigningKey is a base64 encoded private key used to add a JWT-signature.
	// https://www.pomerium.io/docs/signed-headers.html
	SigningKey string `envconfig:"SIGNING_KEY"`
	// SharedKey is a 32 byte random key used to authenticate access between services.
	SharedKey string `envconfig:"SHARED_SECRET"`

	// Session/Cookie management
	CookieName     string
	CookieSecret   string        `envconfig:"COOKIE_SECRET"`
	CookieDomain   string        `envconfig:"COOKIE_DOMAIN"`
	CookieSecure   bool          `envconfig:"COOKIE_SECURE"`
	CookieHTTPOnly bool          `envconfig:"COOKIE_HTTP_ONLY"`
	CookieExpire   time.Duration `envconfig:"COOKIE_EXPIRE"`
	CookieRefresh  time.Duration `envconfig:"COOKIE_REFRESH"`

	// Sub-routes
	Routes                 map[string]string `envconfig:"ROUTES"`
	DefaultUpstreamTimeout time.Duration     `envconfig:"DEFAULT_UPSTREAM_TIMEOUT"`
}

// NewOptions returns a new options struct
var defaultOptions = &Options{
	CookieName:             "_pomerium_proxy",
	CookieHTTPOnly:         true,
	CookieSecure:           true,
	CookieExpire:           time.Duration(14) * time.Hour,
	CookieRefresh:          time.Duration(30) * time.Minute,
	DefaultUpstreamTimeout: time.Duration(30) * time.Second,
}

// OptionsFromEnvConfig builds the identity provider service's configuration
// options from provided environmental variables
func OptionsFromEnvConfig() (*Options, error) {
	o := defaultOptions
	if err := envconfig.Process("", o); err != nil {
		return nil, err
	}
	return o, nil
}

// Validate checks that proper configuration settings are set to create
// a proper Proxy instance
func (o *Options) Validate() error {
	if len(o.Routes) != 0 {
		return errors.New("routes setting is deprecated, use policy instead")
	}
	if o.Policy == "" && o.PolicyFile == "" {
		return errors.New("proxy: either `POLICY` or `POLICY_FILE` must be non-nil")
	}
	var err error
	if o.Policy != "" {
		confBytes, err := base64.StdEncoding.DecodeString(o.Policy)
		if err != nil {
			return fmt.Errorf("proxy: `POLICY` is invalid base64 %v", err)
		}
		_, err = policy.FromConfig(confBytes)
		if err != nil {
			return fmt.Errorf("proxy: `POLICY` %v", err)
		}
	}
	if o.PolicyFile != "" {
		_, err = policy.FromConfigFile(o.PolicyFile)
		if err != nil {
			return fmt.Errorf("proxy: `POLICY_FILE` %v", err)
		}
	}

	if o.AuthenticateURL == nil {
		return errors.New("missing setting: authenticate-service-url")
	}
	if o.AuthenticateURL.Scheme != "https" {
		return errors.New("authenticate-service-url must be a valid https url")
	}
	if o.AuthorizeURL == nil {
		return errors.New("missing setting: authorize-service-url")
	}
	if o.AuthorizeURL.Scheme != "https" {
		return errors.New("authorize-service-url must be a valid https url")
	}
	if o.CookieSecret == "" {
		return errors.New("missing setting: cookie-secret")
	}
	if o.SharedKey == "" {
		return errors.New("missing setting: client-secret")
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

	redirectURL *url.URL
	templates   *template.Template
	mux         map[string]http.Handler
}

// New takes a Proxy service from options and a validation function.
// Function returns an error if options fail to validate.
func New(opts *Options) (*Proxy, error) {
	if opts == nil {
		return nil, errors.New("options cannot be nil")
	}
	if err := opts.Validate(); err != nil {
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

	p := &Proxy{
		mux: make(map[string]http.Handler),
		// services
		AuthenticateURL: opts.AuthenticateURL,
		// session state
		cipher:       cipher,
		csrfStore:    cookieStore,
		sessionStore: cookieStore,
		SharedKey:    opts.SharedKey,
		redirectURL:  &url.URL{Path: "/.pomerium/callback"},
		templates:    templates.New(),
	}
	var policies []policy.Policy
	if opts.Policy != "" {
		confBytes, _ := base64.StdEncoding.DecodeString(opts.Policy)
		policies, _ = policy.FromConfig(confBytes)
	} else {
		policies, _ = policy.FromConfigFile(opts.PolicyFile)
	}
	for _, route := range policies {
		proxy := NewReverseProxy(route.Destination)
		handler, err := NewReverseProxyHandler(opts, proxy, &route)
		if err != nil {
			return nil, err
		}
		p.Handle(route.Source.Host, handler)
		log.Info().Str("src", route.Source.Host).Str("dst", route.Destination.Host).Msg("proxy: new route")
	}

	p.AuthenticateClient, err = clients.NewAuthenticateClient("grpc",
		&clients.Options{
			Addr:                    opts.AuthenticateURL.Host,
			InternalAddr:            opts.AuthenticateInternalAddr,
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
	return proxy
}

// NewReverseProxyHandler applies handler specific options to a given route.
func NewReverseProxyHandler(o *Options, proxy *httputil.ReverseProxy, route *policy.Policy) (http.Handler, error) {
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
	return http.TimeoutHandler(up, timeout, timeoutMsg), nil
}

// urlParse wraps url.Parse to add a scheme if none-exists.
// https://github.com/golang/go/issues/12585
func urlParse(uri string) (*url.URL, error) {
	if !strings.Contains(uri, "://") {
		uri = fmt.Sprintf("https://%s", uri)
	}
	return url.ParseRequestURI(uri)
}
