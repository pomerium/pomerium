package config // import "github.com/pomerium/pomerium/internal/config"

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/urlutil"

	"github.com/mitchellh/hashstructure"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

// DisableHeaderKey is the key used to check whether to disable setting header
const DisableHeaderKey = "disable"

// Options are the global environmental flags used to set up pomerium's services.
// Use NewXXXOptions() methods for a safely initialized data structure.
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
	// HTTPS requests. If empty, ":443" (localhost:443) is used.
	Addr string `mapstructure:"address"`

	// InsecureServer when enabled disables all transport security.
	// In this mode, Pomerium is susceptible to man-in-the-middle attacks.
	// This should be used only for testing.
	InsecureServer bool `mapstructure:"insecure_server"`

	// Cert and Key is the x509 certificate used to hydrate TLSCertificate
	Cert string `mapstructure:"certificate"`
	Key  string `mapstructure:"certificate_key"`

	// CertFile and KeyFile is the x509 certificate used to hydrate TLSCertificate
	CertFile string `mapstructure:"certificate_file"`
	KeyFile  string `mapstructure:"certificate_key_file"`

	// TLSCertificate is the hydrated tls.Certificate.
	TLSCertificate *tls.Certificate

	// HttpRedirectAddr, if set, specifies the host and port to run the HTTP
	// to HTTPS redirect server on. If empty, no redirect server is started.
	HTTPRedirectAddr string `mapstructure:"http_redirect_addr"`

	// Timeout settings : https://github.com/pomerium/pomerium/issues/40
	ReadTimeout       time.Duration `mapstructure:"timeout_read"`
	WriteTimeout      time.Duration `mapstructure:"timeout_write"`
	ReadHeaderTimeout time.Duration `mapstructure:"timeout_read_header"`
	IdleTimeout       time.Duration `mapstructure:"timeout_idle"`

	// Policies define per-route configuration and access control policies.
	Policies   []Policy
	PolicyEnv  string
	PolicyFile string `mapstructure:"policy_file"`

	// AuthenticateURL represents the externally accessible http endpoints
	// used for authentication requests and callbacks
	AuthenticateURLString string `mapstructure:"authenticate_service_url"`
	AuthenticateURL       *url.URL

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

	// Administrators contains a set of emails with users who have super user
	// (sudo) access including the ability to impersonate other users' access
	Administrators []string `mapstructure:"administrators"`

	// AuthorizeURL is the routable destination of the authorize service's
	// gRPC endpoint. NOTE: As many load balancers do not support
	// externally routed gRPC so this may be an internal location.
	AuthorizeURLString string `mapstructure:"authorize_service_url"`
	AuthorizeURL       *url.URL

	// Settings to enable custom behind-the-ingress service communication
	OverrideCertificateName string `mapstructure:"override_certificate_name"`
	CA                      string `mapstructure:"certificate_authority"`
	CAFile                  string `mapstructure:"certificate_authority_file"`

	// SigningKey is the private key used to add a JWT-signature.
	// https://www.pomerium.io/docs/signed-headers.html
	SigningKey string `mapstructure:"signing_key"`

	// Headers to set on all proxied requests. Add a 'disable' key map to turn off.
	HeadersEnv string
	Headers    map[string]string

	// RefreshCooldown limits the rate a user can refresh her session
	RefreshCooldown time.Duration `mapstructure:"refresh_cooldown"`

	//Routes                 map[string]string `mapstructure:"routes"`
	DefaultUpstreamTimeout time.Duration `mapstructure:"default_upstream_timeout"`

	// Address/Port to bind to for prometheus metrics
	MetricsAddr string `mapstructure:"metrics_address"`

	// Tracing shared settings
	TracingProvider string `mapstructure:"tracing_provider"`
	TracingDebug    bool   `mapstructure:"tracing_debug"`

	//  Jaeger
	//
	// CollectorEndpoint is the full url to the Jaeger HTTP Thrift collector.
	// For example, http://localhost:14268/api/traces
	TracingJaegerCollectorEndpoint string `mapstructure:"tracing_jaeger_collector_endpoint"`
	// AgentEndpoint instructs exporter to send spans to jaeger-agent at this address.
	// For example, localhost:6831.
	TracingJaegerAgentEndpoint string `mapstructure:"tracing_jaeger_agent_endpoint"`

	// GRPC Service Settings

	// GRPCAddr specifies the host and port on which the server should serve
	// gRPC requests. If running in all-in-one mode, ":5443" (localhost:5443) is used.
	GRPCAddr string `mapstructure:"grpc_address"`

	// GRPCInsecure disables transport security.
	// If running in all-in-one mode, defaults to true.
	GRPCInsecure bool `mapstructure:"grpc_insecure"`

	GRPCClientTimeout       time.Duration `mapstructure:"grpc_client_timeout"`
	GRPCClientDNSRoundRobin bool          `mapstructure:"grpc_client_dns_roundrobin"`

	// ForwardAuthEndpoint allows for a given route to be used as a forward-auth
	// endpoint instead of a reverse proxy. Some third-party proxies that do not
	// have rich access control capabilities (nginx, envoy, ambassador, traefik)
	// allow you to delegate and authenticate each request to your website
	// with an external server or service. Pomerium can be configured to accept
	// these requests with this switch
	//
	// todo(bdd): link to docs
	ForwardAuthURLString string `mapstructure:"forward_auth_url"`
	ForwardAuthURL       *url.URL

	viper *viper.Viper
}

// DefaultOptions are the default configuration options for pomerium
var defaultOptions = Options{
	Debug:                  false,
	LogLevel:               "debug",
	Services:               "all",
	CookieHTTPOnly:         true,
	CookieSecure:           true,
	CookieExpire:           14 * time.Hour,
	CookieRefresh:          30 * time.Minute,
	CookieName:             "_pomerium",
	DefaultUpstreamTimeout: 30 * time.Second,
	Headers: map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "SAMEORIGIN",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
	},
	Addr:                    ":443",
	ReadHeaderTimeout:       10 * time.Second,
	ReadTimeout:             30 * time.Second,
	WriteTimeout:            0, // support streaming by default
	IdleTimeout:             5 * time.Minute,
	RefreshCooldown:         5 * time.Minute,
	GRPCAddr:                ":443",
	GRPCClientTimeout:       10 * time.Second, // Try to withstand transient service failures for a single request
	GRPCClientDNSRoundRobin: true,
}

// NewDefaultOptions returns a copy the default options. It's the caller's
// responsibility to do a follow up Validate call.
func NewDefaultOptions() *Options {
	newOpts := defaultOptions
	newOpts.viper = viper.New()
	return &newOpts
}

// NewOptionsFromConfig builds the main binary's configuration options by parsing
// environmental variables and config file
func NewOptionsFromConfig(configFile string) (*Options, error) {
	o, err := optionsFromViper(configFile)
	if err != nil {
		return nil, fmt.Errorf("internal/config: options from viper %w", err)
	}
	if o.Debug {
		log.SetDebugMode()
	}
	if o.LogLevel != "" {
		log.SetLevel(o.LogLevel)
	}
	metrics.AddPolicyCountCallback(o.Services, func() int64 {
		return int64(len(o.Policies))
	})

	checksumDec, err := strconv.ParseUint(o.Checksum(), 16, 64)
	if err != nil {
		log.Warn().Err(err).Msg("internal/config: could not parse config checksum into decimal")
	}
	metrics.SetConfigChecksum(o.Services, checksumDec)

	return o, nil
}

func optionsFromViper(configFile string) (*Options, error) {
	// start a copy of the default options
	o := NewDefaultOptions()
	// New viper instance to save into Options later
	v := viper.New()
	// Load up config
	err := bindEnvs(o, v)
	if err != nil {
		return nil, fmt.Errorf("failed to bind options to env vars: %w", err)
	}

	if configFile != "" {
		v.SetConfigFile(configFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
	}

	if err := v.Unmarshal(&o); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	o.viper = v

	if err := o.Validate(); err != nil {
		return nil, fmt.Errorf("validation error %w", err)
	}
	return o, nil
}

// parsePolicy initializes policy to the options from either base64 environmental
// variables or from a file
func (o *Options) parsePolicy() error {
	var policies []Policy
	// Parse from base64 env var
	if o.PolicyEnv != "" {
		policyBytes, err := base64.StdEncoding.DecodeString(o.PolicyEnv)
		if err != nil {
			return fmt.Errorf("could not decode POLICY env var: %w", err)
		}
		if err := yaml.Unmarshal(policyBytes, &policies); err != nil {
			return fmt.Errorf("could not unmarshal policy yaml: %w", err)
		}
	} else if err := o.viperUnmarshalKey("policy", &policies); err != nil {
		return err
	}
	if len(policies) != 0 {
		o.Policies = policies
	}
	// Finish initializing policies
	for i := range o.Policies {
		if err := (&o.Policies[i]).Validate(); err != nil {
			return err
		}
	}
	return nil
}

// OnConfigChange starts a go routine and watches for any changes. If any are
// detected, via an fsnotify event the provided function is run.
func (o *Options) OnConfigChange(run func(in fsnotify.Event)) {
	go o.viper.WatchConfig()
	o.viper.OnConfigChange(run)
}

func (o *Options) viperUnmarshalKey(key string, rawVal interface{}) error {
	return o.viper.UnmarshalKey(key, &rawVal)
}

func (o *Options) viperSet(key string, value interface{}) {
	o.viper.Set(key, value)
}

func (o *Options) viperIsSet(key string) bool {
	return o.viper.IsSet(key)
}

// parseHeaders handles unmarshalling any custom headers correctly from the
// environment or viper's parsed keys
func (o *Options) parseHeaders() error {
	var headers map[string]string
	if o.HeadersEnv != "" {
		// Handle JSON by default via viper
		if headers = o.viper.GetStringMapString("HeadersEnv"); len(headers) == 0 {
			// Try to parse "Key1:Value1,Key2:Value2" syntax
			headerSlice := strings.Split(o.HeadersEnv, ",")
			for n := range headerSlice {
				headerFields := strings.SplitN(headerSlice[n], ":", 2)
				if len(headerFields) == 2 {
					headers[headerFields[0]] = headerFields[1]

				} else {
					// Something went wrong
					return fmt.Errorf("failed to decode headers from '%s'", o.HeadersEnv)
				}
			}

		}
		o.Headers = headers
	} else if o.viperIsSet("headers") {
		if err := o.viperUnmarshalKey("headers", &headers); err != nil {
			return fmt.Errorf("header %s failed to parse: %s", o.viper.Get("headers"), err)
		}
		o.Headers = headers
	}
	return nil
}

// bindEnvs binds a viper instance to each env var of an Options struct based
// on the mapstructure tag
func bindEnvs(o *Options, v *viper.Viper) error {
	tagName := `mapstructure`
	t := reflect.TypeOf(*o)

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		envName := field.Tag.Get(tagName)
		err := v.BindEnv(envName)
		if err != nil {
			return fmt.Errorf("failed to bind field '%s' to env var '%s': %w", field.Name, envName, err)
		}

	}

	// Statically bind fields
	err := v.BindEnv("PolicyEnv", "POLICY")
	if err != nil {
		return fmt.Errorf("failed to bind field 'PolicyEnv' to env var 'POLICY': %w", err)
	}
	err = v.BindEnv("HeadersEnv", "HEADERS")
	if err != nil {
		return fmt.Errorf("failed to bind field 'HeadersEnv' to env var 'HEADERS': %w", err)
	}

	return nil
}

// Validate ensures the Options fields are valid, and hydrated.
func (o *Options) Validate() error {
	var err error

	if !IsValidService(o.Services) {
		return fmt.Errorf("internal/config: %s is an invalid service type", o.Services)
	}

	if IsAll(o.Services) {
		// mutual auth between services on the same host can be generated at runtime
		if o.SharedKey == "" {
			o.SharedKey = cryptutil.NewBase64Key()
		}
		// in all in one mode we are running just over the local socket
		o.GRPCInsecure = true
		// to avoid port collision when running on localhost
		if o.GRPCAddr == defaultOptions.GRPCAddr {
			o.GRPCAddr = ":5443"
		}
		// and we can set the corresponding client
		if o.AuthorizeURLString == "" {
			o.AuthorizeURLString = "https://localhost:5443"
		}
	}

	if o.SharedKey == "" {
		return errors.New("internal/config: shared-key cannot be empty")
	}

	if o.AuthenticateURLString != "" {
		u, err := urlutil.ParseAndValidateURL(o.AuthenticateURLString)
		if err != nil {
			return fmt.Errorf("internal/config: bad authenticate-url %s : %v", o.AuthenticateURLString, err)
		}
		o.AuthenticateURL = u
	}

	if o.AuthorizeURLString != "" {
		u, err := urlutil.ParseAndValidateURL(o.AuthorizeURLString)
		if err != nil {
			return fmt.Errorf("internal/config: bad authorize-url %s : %w", o.AuthorizeURLString, err)
		}
		o.AuthorizeURL = u
	}

	if o.ForwardAuthURLString != "" {
		u, err := urlutil.ParseAndValidateURL(o.ForwardAuthURLString)
		if err != nil {
			return fmt.Errorf("internal/config: bad forward-auth-url %s : %w", o.ForwardAuthURLString, err)
		}
		o.ForwardAuthURL = u
	}

	if o.PolicyFile != "" {
		return errors.New("internal/config: policy file setting is deprecated")
	}
	if err := o.parsePolicy(); err != nil {
		return fmt.Errorf("internal/config: failed to parse policy: %w", err)
	}

	if err := o.parseHeaders(); err != nil {
		return fmt.Errorf("internal/config: failed to parse headers: %w", err)
	}

	if _, disable := o.Headers[DisableHeaderKey]; disable {
		o.Headers = make(map[string]string)
	}

	if o.InsecureServer {
		log.Warn().Msg("internal/config: insecure mode enabled")
	} else if o.Cert != "" || o.Key != "" {
		o.TLSCertificate, err = cryptutil.CertifcateFromBase64(o.Cert, o.Key)
	} else if o.CertFile != "" || o.KeyFile != "" {
		o.TLSCertificate, err = cryptutil.CertificateFromFile(o.CertFile, o.KeyFile)
	} else {
		err = errors.New("internal/config:no certificates supplied nor was insecure mode set")
	}
	if err != nil {
		return err
	}
	return nil
}

// OptionsUpdater updates local state based on an Options struct
type OptionsUpdater interface {
	UpdateOptions(Options) error
}

// Checksum returns the checksum of the current options struct
func (o *Options) Checksum() string {
	hash, err := hashstructure.Hash(o, nil)
	if err != nil {
		log.Warn().Err(err).Msg("internal/config: checksum failure")
		return "no checksum available"
	}
	return fmt.Sprintf("%x", hash)
}

func HandleConfigUpdate(configFile string, opt *Options, services []OptionsUpdater) *Options {
	newOpt, err := NewOptionsFromConfig(configFile)
	if err != nil {
		log.Error().Err(err).Msg("internal/config: could not reload configuration")
		metrics.SetConfigInfo(opt.Services, false, "")
		return opt
	}
	optChecksum := opt.Checksum()
	newOptChecksum := newOpt.Checksum()

	log.Debug().Str("old-checksum", optChecksum).Str("new-checksum", newOptChecksum).Msg("internal/config: checksum change")

	if newOptChecksum == optChecksum {
		log.Debug().Msg("internal/config: loaded configuration has not changed")
		return opt
	}

	var updateFailed bool
	for _, service := range services {
		if err := service.UpdateOptions(*newOpt); err != nil {
			log.Error().Err(err).Msg("internal/config: could not update options")
			updateFailed = true
			metrics.SetConfigInfo(opt.Services, false, "")
		}
	}

	if !updateFailed {
		metrics.SetConfigInfo(newOpt.Services, true, newOptChecksum)
	}
	return newOpt
}
