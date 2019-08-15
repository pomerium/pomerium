package config // import "github.com/pomerium/pomerium/internal/config"

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/fileutil"
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

	// Cert and Key specifies the TLS certificates to use.
	Cert string `mapstructure:"certificate"`
	Key  string `mapstructure:"certificate_key"`

	// CertFile and KeyFile specifies the TLS certificates to use.
	CertFile string `mapstructure:"certificate_file"`
	KeyFile  string `mapstructure:"certificate_key_file"`

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

	// AuthenticateInternalAddr is used override the routable destination of
	// authenticate service's GRPC endpoint.
	// NOTE: As many load balancers do not support externally routed gRPC so
	// this may be an internal location.
	AuthenticateInternalAddrString string `mapstructure:"authenticate_internal_url"`
	AuthenticateInternalAddr       *url.URL

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

	// CollectorEndpoint is the full url to the Jaeger HTTP Thrift collector.
	// For example, http://localhost:14268/api/traces
	TracingJaegerCollectorEndpoint string `mapstructure:"tracing_jaeger_collector_endpoint"`
	// AgentEndpoint instructs exporter to send spans to jaeger-agent at this address.
	// For example, localhost:6831.
	TracingJaegerAgentEndpoint string `mapstructure:"tracing_jaeger_agent_endpoint"`

	// GRPC Service Settings
	GRPCClientTimeout       time.Duration `mapstructure:"grpc_client_timeout"`
	GRPCClientDNSRoundRobin bool          `mapstructure:"grpc_client_dns_roundrobin"`
}

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
	CertFile:                filepath.Join(fileutil.Getwd(), "cert.pem"),
	KeyFile:                 filepath.Join(fileutil.Getwd(), "privkey.pem"),
	ReadHeaderTimeout:       10 * time.Second,
	ReadTimeout:             30 * time.Second,
	WriteTimeout:            0, // support streaming by default
	IdleTimeout:             5 * time.Minute,
	RefreshCooldown:         5 * time.Minute,
	GRPCClientTimeout:       10 * time.Second, // Try to withstand transient service failures for a single request
	GRPCClientDNSRoundRobin: true,
}

// NewOptions returns a minimal options configuration built from default options.
// Any modifications to the structure should be followed up by a subsequent
// call to validate.
func NewOptions(authenticateURL, authorizeURL string) (*Options, error) {
	o := defaultOptions
	o.AuthenticateURLString = authenticateURL
	o.AuthorizeURLString = authorizeURL
	if err := o.Validate(); err != nil {
		return nil, fmt.Errorf("internal/config: validation error %s", err)
	}
	return &o, nil
}

// OptionsFromViper builds the main binary's configuration
// options by parsing environmental variables and config file
func OptionsFromViper(configFile string) (*Options, error) {
	// start a copy of the default options
	o := defaultOptions
	// Load up config
	o.bindEnvs()
	if configFile != "" {
		viper.SetConfigFile(configFile)
		if err := viper.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("internal/config: failed to read config: %s", err)
		}
	}

	if err := viper.Unmarshal(&o); err != nil {
		return nil, fmt.Errorf("internal/config: failed to unmarshal config: %s", err)
	}

	if err := o.Validate(); err != nil {
		return nil, fmt.Errorf("internal/config: validation error %s", err)
	}
	return &o, nil
}

// Validate ensures the Options fields are properly formed, present, and hydrated.
func (o *Options) Validate() error {
	if !IsValidService(o.Services) {
		return fmt.Errorf("%s is an invalid service type", o.Services)
	}

	// shared key must be set for all modes other than "all"
	if o.SharedKey == "" {
		if o.Services == "all" {
			o.SharedKey = cryptutil.GenerateRandomString(32)
		} else {
			return errors.New("shared-key cannot be empty")
		}
	}

	if o.AuthenticateURLString != "" {
		u, err := urlutil.ParseAndValidateURL(o.AuthenticateURLString)
		if err != nil {
			return fmt.Errorf("bad authenticate-url %s : %v", o.AuthenticateURLString, err)
		}
		o.AuthenticateURL = u
	}

	if o.AuthorizeURLString != "" {
		u, err := urlutil.ParseAndValidateURL(o.AuthorizeURLString)
		if err != nil {
			return fmt.Errorf("bad authorize-url %s : %v", o.AuthorizeURLString, err)
		}
		o.AuthorizeURL = u
	}

	if o.AuthenticateInternalAddrString != "" {
		u, err := urlutil.ParseAndValidateURL(o.AuthenticateInternalAddrString)
		if err != nil {
			return fmt.Errorf("bad authenticate-internal-addr %s : %v", o.AuthenticateInternalAddrString, err)
		}
		o.AuthenticateInternalAddr = u
	}
	if o.PolicyFile != "" {
		return errors.New("policy file setting is deprecated")
	}
	if err := o.parsePolicy(); err != nil {
		return fmt.Errorf("failed to parse policy: %s", err)
	}

	if err := o.parseHeaders(); err != nil {
		return fmt.Errorf("failed to parse headers: %s", err)
	}

	if _, disable := o.Headers[DisableHeaderKey]; disable {
		o.Headers = make(map[string]string)
	}

	return nil
}

// parsePolicy initializes policy to the options from either base64 environmental
// variables or from a file
func (o *Options) parsePolicy() error {
	var policies []Policy
	// Parse from base64 env var
	if o.PolicyEnv != "" {
		policyBytes, err := base64.StdEncoding.DecodeString(o.PolicyEnv)
		if err != nil {
			return fmt.Errorf("could not decode POLICY env var: %s", err)
		}
		if err := yaml.Unmarshal(policyBytes, &policies); err != nil {
			return fmt.Errorf("could not unmarshal policy yaml: %s", err)
		}
	} else if err := viper.UnmarshalKey("policy", &policies); err != nil {
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

// parseHeaders handles unmarshalling any custom headers correctly from the
// environment or viper's parsed keys
func (o *Options) parseHeaders() error {
	var headers map[string]string
	if o.HeadersEnv != "" {
		// Handle JSON by default via viper
		if headers = viper.GetStringMapString("HeadersEnv"); len(headers) == 0 {
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
	} else if viper.IsSet("headers") {
		if err := viper.UnmarshalKey("headers", &headers); err != nil {
			return fmt.Errorf("header %s failed to parse: %s", viper.Get("headers"), err)
		}
		o.Headers = headers
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
	viper.BindEnv("HeadersEnv", "HEADERS")
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

func ParseOptions(configFile string) (*Options, error) {
	o, err := OptionsFromViper(configFile)
	if err != nil {
		return nil, err
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

func HandleConfigUpdate(configFile string, opt *Options, services []OptionsUpdater) *Options {
	newOpt, err := ParseOptions(configFile)
	if err != nil {
		log.Error().Err(err).Msg("config: could not reload configuration")
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

	errored := false
	for _, service := range services {
		if err := service.UpdateOptions(*newOpt); err != nil {
			log.Error().Err(err).Msg("internal/config: could not update options")
			errored = true
			metrics.SetConfigInfo(opt.Services, false, "")
		}
	}

	if !errored {
		metrics.SetConfigInfo(newOpt.Services, true, newOptChecksum)
	}
	return newOpt
}
