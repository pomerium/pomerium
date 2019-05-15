package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/pomerium/envconfig"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/policy"
)

// DisableHeaderKey is the key used to check whether to disable setting header
const DisableHeaderKey = "disable"

// Options are the global environmental flags used to set up pomerium's services.
// If a base64 encoded certificate and key are not provided as environmental variables,
// or if a file location is not provided, the server will attempt to find a matching keypair
// in the local directory as `./cert.pem` and `./privkey.pem` respectively.
type Options struct {
	// Debug outputs human-readable logs to Stdout.
	Debug bool `envconfig:"POMERIUM_DEBUG"`

	// LogLevel sets the global override for log level. All Loggers will use at least this value.
	// Possible options are "info","warn", and "error". Defaults to "debug".
	LogLevel string `envconfig:"LOG_LEVEL"`

	// SharedKey is the shared secret authorization key used to mutually authenticate
	// requests between services.
	SharedKey string `envconfig:"SHARED_SECRET"`

	// Services is a list enabled service mode. If none are selected, "all" is used.
	// Available options are : "all", "authenticate", "proxy".
	Services string `envconfig:"SERVICES"`

	// Addr specifies the host and port on which the server should serve
	// HTTPS requests. If empty, ":https" is used.
	Addr string `envconfig:"ADDRESS"`

	// Cert and Key specifies the base64 encoded TLS certificates to use.
	Cert string `envconfig:"CERTIFICATE"`
	Key  string `envconfig:"CERTIFICATE_KEY"`

	// CertFile and KeyFile specifies the TLS certificates to use.
	CertFile string `envconfig:"CERTIFICATE_FILE"`
	KeyFile  string `envconfig:"CERTIFICATE_KEY_FILE"`

	// HttpRedirectAddr, if set, specifies the host and port to run the HTTP
	// to HTTPS redirect server on. For example, ":http" would start a server
	// on port 80.  If empty, no redirect server is started.
	HTTPRedirectAddr string `envconfig:"HTTP_REDIRECT_ADDR"`

	// Timeout settings : https://github.com/pomerium/pomerium/issues/40
	ReadTimeout       time.Duration `envconfig:"TIMEOUT_READ"`
	WriteTimeout      time.Duration `envconfig:"TIMEOUT_WRITE"`
	ReadHeaderTimeout time.Duration `envconfig:"TIMEOUT_READ_HEADER"`
	IdleTimeout       time.Duration `envconfig:"TIMEOUT_IDLE"`

	// Policy is a base64 encoded yaml blob which enumerates
	// per-route access control policies.
	Policy     string `envconfig:"POLICY"`
	PolicyFile string `envconfig:"POLICY_FILE"`

	// AuthenticateURL represents the externally accessible http endpoints
	// used for authentication requests and callbacks
	AuthenticateURL *url.URL `envconfig:"AUTHENTICATE_SERVICE_URL"`

	// Session/Cookie management
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
	AuthenticateCookieName string
	ProxyCookieName        string
	CookieSecret           string        `envconfig:"COOKIE_SECRET"`
	CookieDomain           string        `envconfig:"COOKIE_DOMAIN"`
	CookieSecure           bool          `envconfig:"COOKIE_SECURE"`
	CookieHTTPOnly         bool          `envconfig:"COOKIE_HTTP_ONLY"`
	CookieExpire           time.Duration `envconfig:"COOKIE_EXPIRE"`
	CookieRefresh          time.Duration `envconfig:"COOKIE_REFRESH"`

	// Identity provider configuration variables as specified by RFC6749
	// https://openid.net/specs/openid-connect-basic-1_0.html#RFC6749
	ClientID       string   `envconfig:"IDP_CLIENT_ID"`
	ClientSecret   string   `envconfig:"IDP_CLIENT_SECRET"`
	Provider       string   `envconfig:"IDP_PROVIDER"`
	ProviderURL    string   `envconfig:"IDP_PROVIDER_URL"`
	Scopes         []string `envconfig:"IDP_SCOPES"`
	ServiceAccount string   `envconfig:"IDP_SERVICE_ACCOUNT"`

	Policies []policy.Policy `envconfig:"POLICY"`

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

	// Headers to set on all proxied requests. Add a 'disable' key map to turn off.
	Headers map[string]string `envconfig:"HEADERS"`

	// Sub-routes
	Routes                 map[string]string `envconfig:"ROUTES"`
	DefaultUpstreamTimeout time.Duration     `envconfig:"DEFAULT_UPSTREAM_TIMEOUT"`
}

// NewOptions returns a new options struct with default vaules
func NewOptions() *Options {
	o := &Options{
		Debug:                  false,
		LogLevel:               "debug",
		Services:               "all",
		AuthenticateCookieName: "_pomerium_authenticate",
		CookieHTTPOnly:         true,
		CookieSecure:           true,
		CookieExpire:           time.Duration(14) * time.Hour,
		CookieRefresh:          time.Duration(30) * time.Minute,
		ProxyCookieName:        "_pomerium_proxy",
		DefaultUpstreamTimeout: time.Duration(30) * time.Second,
		Headers: map[string]string{
			"X-Content-Type-Options":    "nosniff",
			"X-Frame-Options":           "SAMEORIGIN",
			"X-XSS-Protection":          "1; mode=block",
			"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
		},
		Addr:              ":https",
		CertFile:          filepath.Join(findPwd(), "cert.pem"),
		KeyFile:           filepath.Join(findPwd(), "privkey.pem"),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // support streaming by default
		IdleTimeout:       5 * time.Minute,
		AuthenticateURL:   new(url.URL),
		AuthorizeURL:      new(url.URL),
	}
	return o
}

// OptionsFromEnvConfig builds the main binary's configuration
// options from provided environmental variables
func OptionsFromEnvConfig() (*Options, error) {
	o := NewOptions()
	if err := envconfig.Process("", o); err != nil {
		return nil, err
	}
	if !IsValidService(o.Services) {
		return nil, fmt.Errorf("%s is an invalid service type", o.Services)
	}
	if o.SharedKey == "" {
		return nil, errors.New("shared-key cannot be empty")
	}
	if o.Debug {
		log.SetDebugMode()
	}
	if o.LogLevel != "" {
		log.SetLevel(o.LogLevel)
	}
	if _, disable := o.Headers[DisableHeaderKey]; disable {
		o.Headers = make(map[string]string)
	}
	return o, nil
}

// findPwd returns best guess at current working directory
func findPwd() string {
	p, err := os.Getwd()
	if err != nil {
		return "."
	}
	return p
}

// isValidService checks to see if a service is a valid service mode
func IsValidService(s string) bool {
	switch s {
	case
		"all",
		"proxy",
		"authorize",
		"authenticate":
		return true
	}
	return false
}

func IsAuthenticate(s string) bool {
	switch s {
	case
		"all",
		"authenticate":
		return true
	}
	return false
}

func IsAuthorize(s string) bool {
	switch s {
	case
		"all",
		"authorize":
		return true
	}
	return false
}

func IsProxy(s string) bool {
	switch s {
	case
		"all",
		"proxy":
		return true
	}
	return false
}
