package proxy // import "github.com/pomerium/pomerium/proxy"

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	stdlog "log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/pomerium/pomerium/internal/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/metrics"
	"github.com/pomerium/pomerium/internal/middleware"
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
	if o.AuthenticateURL == nil || o.AuthenticateURL.String() == "" {
		return errors.New("missing setting: authenticate-service-url")
	}
	if o.AuthenticateURL.Scheme != "https" {
		return errors.New("authenticate-service-url must be a valid https url")
	}
	if o.AuthorizeURL == nil || o.AuthorizeURL.String() == "" {
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
		decodedSigningKey, err := base64.StdEncoding.DecodeString(o.SigningKey)
		if err != nil {
			return fmt.Errorf("signing key is invalid base64: %v", err)
		}
		_, err = cryptutil.NewES256Signer(decodedSigningKey, "localhost")
		if err != nil {
			return fmt.Errorf("invalid signing key is : %v", err)
		}
	}
	return nil
}

// Proxy stores all the information associated with proxying a request.
type Proxy struct {
	// SharedKey used to mutually authenticate service communication
	SharedKey          string
	AuthenticateURL    *url.URL
	AuthenticateClient clients.Authenticator
	AuthorizeClient    clients.Authorizer

	cipher                 cryptutil.Cipher
	cookieName             string
	csrfStore              sessions.CSRFStore
	defaultUpstreamTimeout time.Duration
	redirectURL            *url.URL
	refreshCooldown        time.Duration
	restStore              sessions.SessionStore
	routeConfigs           map[string]*routeConfig
	sessionStore           sessions.SessionStore
	signingKey             string
	templates              *template.Template
}

type routeConfig struct {
	mux    http.Handler
	policy config.Policy
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
		SharedKey: opts.SharedKey,

		routeConfigs: make(map[string]*routeConfig),
		// services
		AuthenticateURL: opts.AuthenticateURL,

		cipher:                 cipher,
		cookieName:             opts.CookieName,
		csrfStore:              cookieStore,
		defaultUpstreamTimeout: opts.DefaultUpstreamTimeout,
		redirectURL:            &url.URL{Path: "/.pomerium/callback"},
		refreshCooldown:        opts.RefreshCooldown,
		restStore:              restStore,
		sessionStore:           cookieStore,
		signingKey:             opts.SigningKey,
		templates:              templates.New(),
	}

	if err := p.UpdatePolicies(&opts); err != nil {
		return nil, err
	}
	metrics.AddPolicyCountCallback("proxy", func() int64 {
		return int64(len(p.routeConfigs))
	})
	p.AuthenticateClient, err = clients.NewAuthenticateClient("grpc",
		&clients.Options{
			Addr:                    opts.AuthenticateURL,
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
			Addr:                    opts.AuthorizeURL,
			OverrideCertificateName: opts.OverrideCertificateName,
			SharedSecret:            opts.SharedKey,
			CA:                      opts.CA,
			CAFile:                  opts.CAFile,
		})
	return p, err
}

// UpdatePolicies updates the handlers based on the configured policies
func (p *Proxy) UpdatePolicies(opts *config.Options) error {
	routeConfigs := make(map[string]*routeConfig, len(opts.Policies))
	if len(opts.Policies) == 0 {
		log.Warn().Msg("proxy: configuration has no policies")
	}
	for _, policy := range opts.Policies {
		if err := policy.Validate(); err != nil {
			return fmt.Errorf("proxy: couldn't update policies %s", err)
		}
		proxy := NewReverseProxy(policy.Destination)
		// build http transport (roundtripper) middleware chain
		// todo(bdd): this will make vet complain, it is safe
		// and can be replaced with transport.Clone() in go 1.13
		// https://go-review.googlesource.com/c/go/+/174597/
		// https://github.com/golang/go/issues/26013#issuecomment-399481302
		transport := *(http.DefaultTransport.(*http.Transport))
		c := tripper.NewChain()
		c = c.Append(metrics.HTTPMetricsRoundTripper("proxy", policy.Destination.Host))
		if policy.TLSSkipVerify {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		if policy.TLSCustomCA != "" {
			rootCA, err := p.customCAPool(policy.TLSCustomCA)
			if err != nil {
				return fmt.Errorf("proxy: couldn't add custom ca to policy %s", policy.From)
			}
			transport.TLSClientConfig = &tls.Config{RootCAs: rootCA}
		}
		proxy.Transport = c.Then(&transport)

		handler, err := p.newReverseProxyHandler(proxy, &policy)
		if err != nil {
			return err
		}
		routeConfigs[policy.Source.Host] = &routeConfig{
			mux:    handler,
			policy: policy,
		}
	}
	p.routeConfigs = routeConfigs
	return nil
}

// UpstreamProxy stores information for proxying the request to the upstream.
type UpstreamProxy struct {
	name    string
	handler http.Handler
}

// ServeHTTP handles the second (reverse-proxying) leg of pomerium's request flow
func (u *UpstreamProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.handler.ServeHTTP(w, r)
}

// NewReverseProxy returns a new ReverseProxy that routes URLs to the scheme, host, and
// base path provided in target. NewReverseProxy rewrites the Host header.
func NewReverseProxy(to *url.URL) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(to)
	sublogger := log.With().Str("proxy", to.Host).Logger()
	proxy.ErrorLog = stdlog.New(&log.StdLogWrapper{Logger: &sublogger}, "", 0)
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

// newRouteSigner creates a route specific signer.
func (p *Proxy) newRouteSigner(audience string) (cryptutil.JWTSigner, error) {
	decodedSigningKey, err := base64.StdEncoding.DecodeString(p.signingKey)
	if err != nil {
		return nil, err
	}
	return cryptutil.NewES256Signer(decodedSigningKey, audience)
}

func (p *Proxy) customCAPool(cert string) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	decodedCert, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cert: %s", err)
	}
	if ok := certPool.AppendCertsFromPEM(decodedCert); !ok {
		return nil, fmt.Errorf("could not append cert: %s", decodedCert)
	}
	return certPool, nil
}

// newReverseProxyHandler applies handler specific options to a given route.
func (p *Proxy) newReverseProxyHandler(rp *httputil.ReverseProxy, route *config.Policy) (handler http.Handler, err error) {
	handler = &UpstreamProxy{
		name:    route.Destination.Host,
		handler: rp,
	}
	c := middleware.NewChain()
	c = c.Append(middleware.StripPomeriumCookie(p.cookieName))

	// if signing key is set, add signer to middleware
	if len(p.signingKey) != 0 {
		signer, err := p.newRouteSigner(route.Source.Host)
		if err != nil {
			return nil, err
		}
		c = c.Append(middleware.SignRequest(signer, HeaderUserID, HeaderEmail, HeaderGroups, HeaderJWT))
	}
	// websockets cannot use the non-hijackable timeout-handler
	if !route.AllowWebsockets {
		timeout := p.defaultUpstreamTimeout
		if route.UpstreamTimeout != 0 {
			timeout = route.UpstreamTimeout
		}
		timeoutMsg := fmt.Sprintf("%s failed to respond within the %s timeout period", route.Destination.Host, timeout)
		handler = http.TimeoutHandler(handler, timeout, timeoutMsg)
	}

	return c.Then(handler), nil
}

// UpdateOptions updates internal structures based on config.Options
func (p *Proxy) UpdateOptions(o config.Options) error {
	return p.UpdatePolicies(&o)
}
