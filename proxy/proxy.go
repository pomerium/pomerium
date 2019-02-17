package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/pomerium/envconfig"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/templates"
	"github.com/pomerium/pomerium/proxy/authenticator"
)

const (
	// HeaderJWT is the header key for pomerium proxy's JWT signature.
	HeaderJWT = "x-pomerium-jwt-assertion"
	// HeaderUserID represents the header key for the user that is passed to the client.
	HeaderUserID = "x-pomerium-authenticated-user-id"
	// HeaderEmail represents the header key for the email that is passed to the client.
	HeaderEmail = "x-pomerium-authenticated-user-email"
)

// Options represents the configurations available for the proxy service.
type Options struct {
	// Authenticate service settings
	AuthenticateURL          *url.URL `envconfig:"AUTHENTICATE_SERVICE_URL"`
	AuthenticateInternalAddr string   `envconfig:"AUTHENTICATE_INTERNAL_URL"`
	OverrideCertificateName  string   `envconfig:"OVERRIDE_CERTIFICATE_NAME"`
	AuthenticatePort         int      `envconfig:"AUTHENTICATE_SERVICE_PORT"`
	CA                       string   `envconfig:"CERTIFICATE_AUTHORITY"`
	CAFile                   string   `envconfig:"CERTIFICATE_AUTHORITY_FILE"`

	// SigningKey is a base64 encoded private key used to add a JWT-signature to proxied requests.
	// See : https://www.pomerium.io/guide/signed-headers.html
	SigningKey string `envconfig:"SIGNING_KEY"`
	// SharedKey is a 32 byte random key used to authenticate access between services.
	SharedKey string `envconfig:"SHARED_SECRET"`

	// Session/Cookie management
	CookieName        string
	CookieSecret      string        `envconfig:"COOKIE_SECRET"`
	CookieDomain      string        `envconfig:"COOKIE_DOMAIN"`
	CookieSecure      bool          `envconfig:"COOKIE_SECURE"`
	CookieHTTPOnly    bool          `envconfig:"COOKIE_HTTP_ONLY"`
	CookieExpire      time.Duration `envconfig:"COOKIE_EXPIRE"`
	CookieRefresh     time.Duration `envconfig:"COOKIE_REFRESH"`
	CookieLifetimeTTL time.Duration `envconfig:"COOKIE_LIFETIME"`

	// Sub-routes
	Routes                 map[string]string `envconfig:"ROUTES"`
	DefaultUpstreamTimeout time.Duration     `envconfig:"DEFAULT_UPSTREAM_TIMEOUT"`
}

// NewOptions returns a new options struct
var defaultOptions = &Options{
	CookieName:             "_pomerium_proxy",
	CookieHTTPOnly:         true,
	CookieSecure:           true,
	CookieExpire:           time.Duration(168) * time.Hour,
	CookieRefresh:          time.Duration(30) * time.Minute,
	CookieLifetimeTTL:      time.Duration(720) * time.Hour,
	DefaultUpstreamTimeout: time.Duration(10) * time.Second,
	// services
	AuthenticatePort: 443,
}

// OptionsFromEnvConfig builds the IdentityProvider service's configuration
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
	if len(o.Routes) == 0 {
		return errors.New("missing setting: routes")
	}
	for to, from := range o.Routes {
		if _, err := urlParse(to); err != nil {
			return fmt.Errorf("could not parse origin %s as url : %q", to, err)
		}
		if _, err := urlParse(from); err != nil {
			return fmt.Errorf("could not parse destination %s as url : %q", to, err)
		}
	}
	if o.AuthenticateURL == nil {
		return errors.New("missing setting: authenticate-service-url")
	}
	if o.AuthenticateURL.Scheme != "https" {
		return errors.New("authenticate-service-url must be a valid https url")
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

	// services
	AuthenticateURL    *url.URL
	AuthenticateClient authenticator.Authenticator

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
//
// Caller responsible for closing AuthenticateConn.
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

	for from, to := range opts.Routes {
		fromURL, _ := urlParse(from)
		toURL, _ := urlParse(to)
		reverseProxy := NewReverseProxy(toURL)
		handler, err := NewReverseProxyHandler(opts, reverseProxy, fromURL.Host, toURL.Host)
		if err != nil {
			return nil, err
		}
		p.Handle(fromURL.Host, handler)
		log.Info().Str("from", fromURL.Host).Str("to", toURL.String()).Msg("proxy: new route")
	}

	p.AuthenticateClient, err = authenticator.New(
		"grpc",
		&authenticator.Options{
			Addr:                    opts.AuthenticateURL.Host,
			InternalAddr:            opts.AuthenticateInternalAddr,
			OverrideCertificateName: opts.OverrideCertificateName,
			SharedSecret:            opts.SharedKey,
			Port:                    opts.AuthenticatePort,
			CA:                      opts.CA,
			CAFile:                  opts.CAFile,
		})
	return p, nil
}

// UpstreamProxy stores information necessary for proxying the request back to the upstream.
type UpstreamProxy struct {
	name       string
	cookieName string
	handler    http.Handler
	signer     cryptutil.JWTSigner
}

var defaultUpstreamTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}).DialContext,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   30 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
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

func (u *UpstreamProxy) signRequest(req *http.Request) {
	if u.signer != nil {
		jwt, err := u.signer.SignJWT(req.Header.Get(HeaderUserID), req.Header.Get(HeaderEmail))
		if err == nil {
			req.Header.Set(HeaderJWT, jwt)
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
	proxy.Transport = defaultUpstreamTransport

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
func NewReverseProxyHandler(opts *Options, reverseProxy *httputil.ReverseProxy, from, to string) (http.Handler, error) {
	up := &UpstreamProxy{
		name:       to,
		handler:    reverseProxy,
		cookieName: opts.CookieName,
	}
	if len(opts.SigningKey) != 0 {
		decodedSigningKey, err := base64.StdEncoding.DecodeString(opts.SigningKey)
		if err != nil {
			return nil, err
		}
		signer, err := cryptutil.NewES256Signer(decodedSigningKey, from)
		if err != nil {
			return nil, err
		}
		up.signer = signer
	}
	timeout := opts.DefaultUpstreamTimeout
	timeoutMsg := fmt.Sprintf("%s failed to respond within the %s timeout period", to, timeout)
	return http.TimeoutHandler(up, timeout, timeoutMsg), nil
}

// urlParse adds a scheme if none-exists, addressesing a quirk in how
// one may expect url.Parse to function when given scheme-less domain is provided.
//
// see: https://github.com/golang/go/issues/12585
// see: https://golang.org/pkg/net/url/#Parse
func urlParse(uri string) (*url.URL, error) {
	if !strings.Contains(uri, "://") {
		uri = fmt.Sprintf("https://%s", uri)
	}
	return url.Parse(uri)
}
