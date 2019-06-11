package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/mitchellh/hashstructure"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/policy"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

// DisableHeaderKey is the key used to check whether to disable setting header
const DisableHeaderKey = "disable"

// Options are the global environmental flags used to set up pomerium's services.
// If a base64 encoded certificate and key are not provided as environmental variables,
// or if a file location is not provided, the server will attempt to find a matching keypair
// in the local directory as `./cert.pem` and `./privkey.pem` respectively.
type Options struct {
	// Debug outputs human-readable logs to Stdout.
	Debug bool `mapstructure:"pomerium_debug"`

	// LogLevel sets the global override for log level. All Loggers will use at least this value.
	// Possible options are "info","warn", and "error". Defaults to "debug".
	LogLevel string `mapstructure:"log_level"`

	// SharedKey is the shared secret authorization key used to mutually authenticate
	// requests between services.
	SharedKey string `mapstructure:"shared_secret"`

	// Services is a list enabled service mode. If none are selected, "all" is used.
	// Available options are : "all", "authenticate", "proxy".
	Services string `mapstructure:"services"`

	// Addr specifies the host and port on which the server should serve
	// HTTPS requests. If empty, ":https" is used.
	Addr string `mapstructure:"address"`

	// Cert and Key specifies the base64 encoded TLS certificates to use.
	Cert string `mapstructure:"certificate"`
	Key  string `mapstructure:"certificate_key"`

	// CertFile and KeyFile specifies the TLS certificates to use.
	CertFile string `mapstructure:"certificate_file"`
	KeyFile  string `mapstructure:"certificate_key_file"`

	// HttpRedirectAddr, if set, specifies the host and port to run the HTTP
	// to HTTPS redirect server on. For example, ":http" would start a server
	// on port 80.  If empty, no redirect server is started.
	HTTPRedirectAddr string `mapstructure:"http_redirect_addr"`

	// Timeout settings : https://github.com/pomerium/pomerium/issues/40
	ReadTimeout       time.Duration `mapstructure:"timeout_read"`
	WriteTimeout      time.Duration `mapstructure:"timeout_write"`
	ReadHeaderTimeout time.Duration `mapstructure:"timeout_read_header"`
	IdleTimeout       time.Duration `mapstructure:"timeout_idle"`

	// Policy is a base64 encoded yaml blob which enumerates
	// per-route access control policies.
	PolicyEnv  string
	PolicyFile string `mapstructure:"policy_file"`

	// AuthenticateURL represents the externally accessible http endpoints
	// used for authentication requests and callbacks
	AuthenticateURLString string `mapstructure:"authenticate_service_url"`
	AuthenticateURL       url.URL

	// Session/Cookie management
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
	CookieName     string        `mapstructure:"cookie_name"`
	CookieSecret   string        `mapstructure:"cookie_secret"`
	CookieDomain   string        `mapstructure:"cookie_domain"`
	CookieSecure   bool          `mapstructure:"cookie_secure"`
	CookieHTTPOnly bool          `mapstructure:"cookie_http_only"`
	CookieExpire   time.Duration `mapstructure:"cookie_expire"`
	CookieRefresh  time.Duration `mapstructure:"cookie_refresh"`

	// Identity provider configuration variables as specified by RFC6749
	// https://openid.net/specs/openid-connect-basic-1_0.html#RFC6749
	ClientID       string   `mapstructure:"idp_client_id"`
	ClientSecret   string   `mapstructure:"idp_client_secret"`
	Provider       string   `mapstructure:"idp_provider"`
	ProviderURL    string   `mapstructure:"idp_provider_url"`
	Scopes         []string `mapstructure:"idp_scopes"`
	ServiceAccount string   `mapstructure:"idp_service_account"`

	Policies []policy.Policy

	// Administrators contains a set of emails with users who have super user
	// (sudo) access including the ability to impersonate other users' access
	Administrators []string `mapstructure:"administrators"`

	// AuthenticateInternalAddr is used override the routable destination of
	// authenticate service's GRPC endpoint.
	// NOTE: As many load balancers do not support externally routed gRPC so
	// this may be an internal location.
	AuthenticateInternalAddrString string `mapstructure:"authenticate_internal_url"`
	AuthenticateInternalAddr       url.URL

	// AuthorizeURL is the routable destination of the authorize service's
	// gRPC endpoint. NOTE: As many load balancers do not support
	// externally routed gRPC so this may be an internal location.
	AuthorizeURLString string `mapstructure:"authorize_service_url"`
	AuthorizeURL       url.URL

	// Settings to enable custom behind-the-ingress service communication
	OverrideCertificateName string `mapstructure:"override_certificate_name"`
	CA                      string `mapstructure:"certificate_authority"`
	CAFile                  string `mapstructure:"certificate_authority_file"`

	// SigningKey is a base64 encoded private key used to add a JWT-signature.
	// https://www.pomerium.io/docs/signed-headers.html
	SigningKey string `mapstructure:"signing_key"`

	// Headers to set on all proxied requests. Add a 'disable' key map to turn off.
	Headers map[string]string `mapstructure:"headers"`

	// RefreshCooldown limits the rate a user can refresh her session
	RefreshCooldown time.Duration `mapstructure:"refresh_cooldown"`

	// Sub-routes
	Routes                 map[string]string `mapstructure:"routes"`
	DefaultUpstreamTimeout time.Duration     `mapstructure:"default_upstream_timeout"`

	// Enable proxying of websocket connections. Defaults to "false".
	// Caution: Enabling this feature could result in abuse via DOS attacks.
	AllowWebsockets bool `mapstructure:"allow_websockets"`

	// Address/Port to bind to for prometheus metrics
	MetricsAddr string `mapstructure:"metrics_address"`
}

// NewOptions returns a new options struct with default values
func NewOptions() Options {
	o := Options{
		Debug:                  false,
		LogLevel:               "debug",
		Services:               "all",
		CookieHTTPOnly:         true,
		CookieSecure:           true,
		CookieExpire:           time.Duration(14) * time.Hour,
		CookieRefresh:          time.Duration(30) * time.Minute,
		CookieName:             "_pomerium",
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
		RefreshCooldown:   time.Duration(5 * time.Minute),
		AllowWebsockets:   false,
	}
	return o
}

// OptionsFromViper builds the main binary's configuration
// options by parsing environmental variables and config file
func OptionsFromViper(configFile string) (Options, error) {
	o := NewOptions()

	// Load up config
	o.bindEnvs()
	if configFile != "" {
		log.Info().
			Str("file", configFile).
			Msg("loading config from file")

		viper.SetConfigFile(configFile)
		err := viper.ReadInConfig()
		if err != nil {
			return o, fmt.Errorf("failed to read config: %s", err)
		}
	}

	err := viper.Unmarshal(&o)
	if err != nil {
		return o, fmt.Errorf("failed to load options from config: %s", err)
	}

	// Turn URL strings into url structs
	err = o.parseURLs()
	if err != nil {
		return o, fmt.Errorf("failed to parse URLs: %s", err)
	}

	// Load and initialize policy
	err = o.parsePolicy()
	if err != nil {
		return o, fmt.Errorf("failed to parse Policy: %s", err)
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

	err = o.validate()
	if err != nil {
		return o, err
	}

	log.Debug().
		Str("config-checksum", o.Checksum()).
		Msg("read configuration with checksum")
	return o, nil
}

// validate ensures the Options fields are properly formed and present
func (o *Options) validate() error {

	if !IsValidService(o.Services) {
		return fmt.Errorf("%s is an invalid service type", o.Services)
	}

	if o.SharedKey == "" {
		return errors.New("shared-key cannot be empty")
	}

	if len(o.Routes) != 0 {
		return errors.New("routes setting is deprecated, use policy instead")
	}

	if o.PolicyFile != "" {
		return errors.New("Setting POLICY_FILE is deprecated, use policy env var or config file instead")
	}

	return nil
}

// parsePolicy initializes policy
func (o *Options) parsePolicy() error {
	var policies []policy.Policy
	// Parse from base64 env var
	if o.PolicyEnv != "" {
		policyBytes, err := base64.StdEncoding.DecodeString(o.PolicyEnv)
		if err != nil {
			return fmt.Errorf("Could not decode POLICY env var: %s", err)
		}
		if err := yaml.Unmarshal(policyBytes, &policies); err != nil {
			return fmt.Errorf("Could not parse POLICY env var: %s", err)
		}
		// Parse from file
	} else {
		err := viper.UnmarshalKey("policy", &policies)
		if err != nil {
			return err
		}
	}

	// Finish initializing policies
	for i := range policies {
		err := (&policies[i]).Validate()
		if err != nil {
			return err
		}
	}
	o.Policies = policies
	return nil
}

// parseAndValidateURL wraps standard library's default url.Parse because it's much more
// lenient about what type of urls it accepts than pomerium can be.
func parseAndValidateURL(rawurl string) (*url.URL, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%s does have a valid hostname", rawurl)
	}
	if u.Scheme == "" || u.Scheme != "https" {
		return nil, fmt.Errorf("%s does have a valid https scheme", rawurl)
	}
	return u, nil
}

// parseURLs parses URL strings into actual URL pointers
func (o *Options) parseURLs() error {
	if o.AuthenticateURLString != "" {
		AuthenticateURL, err := parseAndValidateURL(o.AuthenticateURLString)
		if err != nil {
			return fmt.Errorf("internal/config: bad authenticate-url %s : %v", o.AuthenticateURLString, err)
		}
		o.AuthenticateURL = *AuthenticateURL
	}

	if o.AuthorizeURLString != "" {
		AuthorizeURL, err := parseAndValidateURL(o.AuthorizeURLString)
		if err != nil {
			return fmt.Errorf("internal/config: bad authorize-url %s : %v", o.AuthorizeURLString, err)
		}
		o.AuthorizeURL = *AuthorizeURL
	}

	if o.AuthenticateInternalAddrString != "" {
		AuthenticateInternalAddr, err := parseAndValidateURL(o.AuthenticateInternalAddrString)
		if err != nil {
			return fmt.Errorf("internal/config: bad authenticate-internal-addr %s : %v", o.AuthenticateInternalAddrString, err)
		}
		o.AuthenticateInternalAddr = *AuthenticateInternalAddr
	}

	return nil
}

// bindEnvs makes sure viper binds to each env var based on the mapstructure tag
func (o *Options) bindEnvs() {
	tagName := `mapstructure`
	t := reflect.TypeOf(*o)

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		envName := field.Tag.Get(tagName)
		viper.BindEnv(envName)
	}

	// Statically bind fields
	viper.BindEnv("PolicyEnv", "POLICY")
}

// findPwd returns best guess at current working directory
func findPwd() string {
	p, err := os.Getwd()
	if err != nil {
		return "."
	}
	return p
}

// IsValidService checks to see if a service is a valid service mode
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

// IsAuthenticate checks to see if we should be running the authenticate service
func IsAuthenticate(s string) bool {
	switch s {
	case
		"all",
		"authenticate":
		return true
	}
	return false
}

// IsAuthorize checks to see if we should be running the authorize service
func IsAuthorize(s string) bool {
	switch s {
	case
		"all",
		"authorize":
		return true
	}
	return false
}

// IsProxy checks to see if we should be running the proxy service
func IsProxy(s string) bool {
	switch s {
	case
		"all",
		"proxy":
		return true
	}
	return false
}

// OptionsUpdater updates local state based on an Options struct
type OptionsUpdater interface {
	UpdateOptions(Options) error
}

// Checksum returns the checksum of the current options struct
func (o *Options) Checksum() string {
	hash, err := hashstructure.Hash(o, nil)

	if err != nil {
		log.Warn().Msg("could not calculate Option checksum")
		return "no checksum availablle"
	}
	return fmt.Sprintf("%x", hash)
}
