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
	"github.com/pomerium/pomerium/internal/aead"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/templates"
	"github.com/pomerium/pomerium/proxy/authenticator"
)

// Options represents the configuration options for the proxy service.
type Options struct {
	// AuthenticateServiceURL specifies the url to the pomerium authenticate http service.
	AuthenticateServiceURL *url.URL `envconfig:"PROVIDER_URL"`

	//	EmailDomains is a string slice of valid domains to proxy
	EmailDomains []string `envconfig:"EMAIL_DOMAIN"`
	// todo(bdd): ClientID and ClientSecret are used are a hacky pre shared key
	// prefer certificates and mutual tls
	ClientID     string `envconfig:"PROXY_CLIENT_ID"`
	ClientSecret string `envconfig:"PROXY_CLIENT_SECRET"`

	DefaultUpstreamTimeout time.Duration `envconfig:"DEFAULT_UPSTREAM_TIMEOUT"`

	CookieName     string        `envconfig:"COOKIE_NAME"`
	CookieSecret   string        `envconfig:"COOKIE_SECRET"`
	CookieDomain   string        `envconfig:"COOKIE_DOMAIN"`
	CookieExpire   time.Duration `envconfig:"COOKIE_EXPIRE"`
	CookieSecure   bool          `envconfig:"COOKIE_SECURE" `
	CookieHTTPOnly bool          `envconfig:"COOKIE_HTTP_ONLY"`

	PassAccessToken bool `envconfig:"PASS_ACCESS_TOKEN"`

	// session details
	SessionValidTTL    time.Duration `envconfig:"SESSION_VALID_TTL"`
	SessionLifetimeTTL time.Duration `envconfig:"SESSION_LIFETIME_TTL"`
	GracePeriodTTL     time.Duration `envconfig:"GRACE_PERIOD_TTL"`

	Routes map[string]string `envconfig:"ROUTES"`
}

// NewOptions returns a new options struct
var defaultOptions = &Options{
	CookieName:             "_pomerium_proxy",
	CookieSecure:           true,
	CookieHTTPOnly:         true,
	CookieExpire:           time.Duration(168) * time.Hour,
	DefaultUpstreamTimeout: time.Duration(10) * time.Second,
	SessionLifetimeTTL:     time.Duration(720) * time.Hour,
	SessionValidTTL:        time.Duration(1) * time.Minute,
	GracePeriodTTL:         time.Duration(3) * time.Hour,
	PassAccessToken:        false,
}

// OptionsFromEnvConfig builds the authentication service's configuration
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
	if o.AuthenticateServiceURL == nil {
		return errors.New("missing setting: provider-url")
	}
	if o.CookieSecret == "" {
		return errors.New("missing setting: cookie-secret")
	}
	if o.ClientID == "" {
		return errors.New("missing setting: client-id")
	}
	if o.ClientSecret == "" {
		return errors.New("missing setting: client-secret")
	}
	if len(o.EmailDomains) == 0 {
		return errors.New("missing setting: email-domain")
	}

	decodedCookieSecret, err := base64.StdEncoding.DecodeString(o.CookieSecret)
	if err != nil {
		return errors.New("cookie secret is invalid (e.g. `head -c33 /dev/urandom | base64`) ")
	}
	validCookieSecretLength := false
	for _, i := range []int{32, 64} {
		if len(decodedCookieSecret) == i {
			validCookieSecretLength = true
		}
	}
	if !validCookieSecretLength {
		return fmt.Errorf("cookie secret is invalid, must be 32 or 64 bytes but got %d bytes (e.g. `head -c33 /dev/urandom | base64`) ", len(decodedCookieSecret))
	}
	return nil
}

// Proxy stores all the information associated with proxying a request.
type Proxy struct {
	CookieCipher   aead.Cipher
	CookieDomain   string
	CookieExpire   time.Duration
	CookieHTTPOnly bool
	CookieName     string
	CookieSecure   bool
	CookieSeed     string
	CSRFCookieName string
	EmailValidator func(string) bool

	PassAccessToken bool

	// services
	authenticateClient *authenticator.AuthenticateClient
	// session
	csrfStore    sessions.CSRFStore
	sessionStore sessions.SessionStore
	cipher       aead.Cipher

	redirectURL *url.URL // the url to receive requests at
	templates   *template.Template
	mux         map[string]*http.Handler
}

// StateParameter holds the redirect id along with the session id.
type StateParameter struct {
	SessionID   string `json:"session_id"`
	RedirectURI string `json:"redirect_uri"`
}

// NewProxy takes a Proxy service from options and a validation function.
// Function returns an error if options fail to validate.
func NewProxy(opts *Options, optFuncs ...func(*Proxy) error) (*Proxy, error) {
	if opts == nil {
		return nil, errors.New("options cannot be nil")
	}
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	// error explicitly handled by validate
	decodedSecret, _ := base64.StdEncoding.DecodeString(opts.CookieSecret)
	cipher, err := aead.NewMiscreantCipher(decodedSecret)
	if err != nil {
		return nil, fmt.Errorf("cookie-secret error: %s", err.Error())
	}

	cookieStore, err := sessions.NewCookieStore(opts.CookieName,
		sessions.CreateMiscreantCookieCipher(decodedSecret),
		func(c *sessions.CookieStore) error {
			c.CookieDomain = opts.CookieDomain
			c.CookieHTTPOnly = opts.CookieHTTPOnly
			c.CookieExpire = opts.CookieExpire
			c.CookieSecure = opts.CookieSecure
			return nil
		})

	if err != nil {
		return nil, err
	}

	authClient := authenticator.NewAuthenticateClient(
		opts.AuthenticateServiceURL,
		// todo(bdd): fields below can be dropped as Client data provides redudent auth
		opts.ClientID,
		opts.ClientSecret,
		// todo(bdd): fields below should be passed as function args
		opts.SessionLifetimeTTL,
		opts.SessionValidTTL,
		opts.GracePeriodTTL,
	)

	p := &Proxy{
		CookieCipher:   cipher,
		CookieDomain:   opts.CookieDomain,
		CookieExpire:   opts.CookieExpire,
		CookieHTTPOnly: opts.CookieHTTPOnly,
		CookieName:     opts.CookieName,
		CookieSecure:   opts.CookieSecure,
		CookieSeed:     string(decodedSecret),
		CSRFCookieName: fmt.Sprintf("%v_%v", opts.CookieName, "csrf"),

		// these fields make up the routing mechanism
		mux: make(map[string]*http.Handler),
		// session state
		csrfStore:    cookieStore,
		sessionStore: cookieStore,
		cipher:       cipher,

		authenticateClient: authClient,
		redirectURL:        &url.URL{Path: "/.pomerium/callback"},
		templates:          templates.New(),
		PassAccessToken:    opts.PassAccessToken,
	}

	for _, optFunc := range optFuncs {
		err := optFunc(p)
		if err != nil {
			return nil, err
		}
	}

	for from, to := range opts.Routes {
		fromURL, _ := urlParse(from)
		toURL, _ := urlParse(to)
		reverseProxy := NewReverseProxy(toURL)
		handler := NewReverseProxyHandler(opts, reverseProxy, toURL.String())
		p.Handle(fromURL.Host, handler)
		log.Info().Str("from", fromURL.Host).Str("to", toURL.String()).Msg("proxy.NewProxy : route")
	}

	log.Info().
		Str("CookieName", p.CookieName).
		Str("redirectURL", p.redirectURL.String()).
		Str("CSRFCookieName", p.CSRFCookieName).
		Bool("CookieSecure", p.CookieSecure).
		Str("CookieDomain", p.CookieDomain).
		Bool("CookieHTTPOnly", p.CookieHTTPOnly).
		Dur("CookieExpire", opts.CookieExpire).
		Msg("proxy.NewProxy")

	return p, nil
}

// UpstreamProxy stores information necessary for proxying the request back to the upstream.
type UpstreamProxy struct {
	name       string
	cookieName string
	handler    http.Handler
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
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// deleteSSOCookieHeader deletes the session cookie from the request header string.
func deleteSSOCookieHeader(req *http.Request, cookieName string) {
	headers := []string{}
	for _, cookie := range req.Cookies() {
		if cookie.Name != cookieName {
			headers = append(headers, cookie.String())
		}
	}
	req.Header.Set("Cookie", strings.Join(headers, ";"))
}

// ServeHTTP signs the http request and deletes cookie headers
// before calling the upstream's ServeHTTP function.
func (u *UpstreamProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestLog := log.WithRequest(r, "proxy.ServeHTTP")
	deleteSSOCookieHeader(r, u.cookieName)
	start := time.Now()
	u.handler.ServeHTTP(w, r)
	duration := time.Since(start)

	requestLog.Debug().Dur("duration", duration).Msg("proxy-request")
}

// NewReverseProxy creates a reverse proxy to a specified url.
// It adds an X-Forwarded-Host header that is the request's host.
//
// todo(bdd): when would we ever want to preserve host?
func NewReverseProxy(to *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(to)
	proxy.Transport = defaultUpstreamTransport
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		req.Header.Add("X-Forwarded-Host", req.Host)
		director(req)
		req.Host = to.Host
	}
	return proxy
}

// NewReverseProxyHandler applies handler specific options to a given
// route.
func NewReverseProxyHandler(opts *Options, reverseProxy *httputil.ReverseProxy, serviceName string) http.Handler {
	upstreamProxy := &UpstreamProxy{
		name:       serviceName,
		handler:    reverseProxy,
		cookieName: opts.CookieName,
	}

	timeout := opts.DefaultUpstreamTimeout
	timeoutMsg := fmt.Sprintf("%s failed to respond within the %s timeout period", serviceName, timeout)
	return http.TimeoutHandler(upstreamProxy, timeout, timeoutMsg)
}

// urlParse adds a scheme if none-exists, addressesing a quirk in how
// one may expect url.Parse to function when a "naked" domain is sent.
//
// see: https://github.com/golang/go/issues/12585
// see: https://golang.org/pkg/net/url/#Parse
func urlParse(uri string) (*url.URL, error) {
	if !strings.Contains(uri, "://") {
		uri = fmt.Sprintf("https://%s", uri)
	}
	return url.Parse(uri)
}
