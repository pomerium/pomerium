package config

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/spf13/viper"

	"github.com/pomerium/pomerium/internal/directory/azure"
	"github.com/pomerium/pomerium/internal/directory/github"
	"github.com/pomerium/pomerium/internal/directory/gitlab"
	"github.com/pomerium/pomerium/internal/directory/google"
	"github.com/pomerium/pomerium/internal/directory/okta"
	"github.com/pomerium/pomerium/internal/directory/onelogin"
	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/internal/identity/oauth"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/config"
)

// DisableHeaderKey is the key used to check whether to disable setting header
const DisableHeaderKey = "disable"

const (
	idpCustomScopesDocLink = "https://www.pomerium.io/reference/#identity-provider-scopes"
	idpCustomScopesWarnMsg = "config: using custom scopes may result in undefined behavior, see: " + idpCustomScopesDocLink
)

// DefaultAlternativeAddr is the address used is two services are competing over
// the same listener. Typically this is invisible to the end user (e.g. localhost)
// gRPC server, or is used for healthchecks (authorize only service)
const DefaultAlternativeAddr = ":5443"

// EnvoyAdminURL indicates where the envoy control plane is listening
var EnvoyAdminURL = &url.URL{Host: "127.0.0.1:9901", Scheme: "http"}

// Options are the global environmental flags used to set up pomerium's services.
// Use NewXXXOptions() methods for a safely initialized data structure.
type Options struct {
	// Debug outputs human-readable logs to Stdout.
	Debug bool `mapstructure:"pomerium_debug" yaml:"pomerium_debug,omitempty"`

	// LogLevel sets the global override for log level. All Loggers will use at least this value.
	// Possible options are "info","warn","debug" and "error". Defaults to "info".
	LogLevel string `mapstructure:"log_level" yaml:"log_level,omitempty"`

	// ProxyLogLevel sets the log level for the proxy service.
	// Possible options are "info","warn", and "error". Defaults to the value of `LogLevel`.
	ProxyLogLevel string `mapstructure:"proxy_log_level" yaml:"proxy_log_level,omitempty"`

	// SharedKey is the shared secret authorization key used to mutually authenticate
	// requests between services.
	SharedKey string `mapstructure:"shared_secret" yaml:"shared_secret,omitempty"`

	// Services is a list enabled service mode. If none are selected, "all" is used.
	// Available options are : "all", "authenticate", "proxy".
	Services string `mapstructure:"services" yaml:"services,omitempty"`

	// Addr specifies the host and port on which the server should serve
	// HTTPS requests. If empty, ":443" (localhost:443) is used.
	Addr string `mapstructure:"address" yaml:"address,omitempty"`

	// InsecureServer when enabled disables all transport security.
	// In this mode, Pomerium is susceptible to man-in-the-middle attacks.
	// This should be used only for testing.
	InsecureServer bool `mapstructure:"insecure_server" yaml:"insecure_server,omitempty"`

	// DNSLookupFamily is the DNS IP address resolution policy.
	// If this setting is not specified, the value defaults to AUTO.
	DNSLookupFamily string `mapstructure:"dns_lookup_family" yaml:"dns_lookup_family,omitempty"`

	CertificateFiles []certificateFilePair `mapstructure:"certificates" yaml:"certificates,omitempty"`

	// Cert and Key is the x509 certificate used to create the HTTPS server.
	Cert string `mapstructure:"certificate" yaml:"certificate,omitempty"`
	Key  string `mapstructure:"certificate_key" yaml:"certificate_key,omitempty"`

	// CertFile and KeyFile is the x509 certificate used to hydrate TLSCertificate
	CertFile string `mapstructure:"certificate_file" yaml:"certificate_file,omitempty"`
	KeyFile  string `mapstructure:"certificate_key_file" yaml:"certificate_key_file,omitempty"`

	Certificates []tls.Certificate `mapstructure:"-" yaml:"-"`

	// HttpRedirectAddr, if set, specifies the host and port to run the HTTP
	// to HTTPS redirect server on. If empty, no redirect server is started.
	HTTPRedirectAddr string `mapstructure:"http_redirect_addr" yaml:"http_redirect_addr,omitempty"`

	// Timeout settings : https://github.com/pomerium/pomerium/issues/40
	ReadTimeout  time.Duration `mapstructure:"timeout_read" yaml:"timeout_read,omitempty"`
	WriteTimeout time.Duration `mapstructure:"timeout_write" yaml:"timeout_write,omitempty"`
	IdleTimeout  time.Duration `mapstructure:"timeout_idle" yaml:"timeout_idle,omitempty"`

	// Policies define per-route configuration and access control policies.
	Policies   []Policy `mapstructure:"policy"`
	PolicyFile string   `mapstructure:"policy_file" yaml:"policy_file,omitempty"`

	// AdditionalPolicies are any additional policies added to the options.
	AdditionalPolicies []Policy `yaml:"-"`

	// AuthenticateURL represents the externally accessible http endpoints
	// used for authentication requests and callbacks
	AuthenticateURLString string   `mapstructure:"authenticate_service_url" yaml:"authenticate_service_url,omitempty"`
	AuthenticateURL       *url.URL `yaml:"-"`
	// SignOutRedirectURL represents the url that  user will be redirected to after signing out.
	SignOutRedirectURLString string   `mapstructure:"signout_redirect_url" yaml:"signout_redirect_url,omitempty"`
	SignOutRedirectURL       *url.URL `yaml:"-"`

	// AuthenticateCallbackPath is the path to the HTTP endpoint that will
	// receive the response from your identity provider. The value must exactly
	// match one of the authorized redirect URIs for the OAuth 2.0 client.
	// Defaults to: `/oauth2/callback`
	AuthenticateCallbackPath string `mapstructure:"authenticate_callback_path" yaml:"authenticate_callback_path,omitempty"`

	// Session/Cookie management
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
	CookieName     string        `mapstructure:"cookie_name" yaml:"cookie_name,omitempty"`
	CookieSecret   string        `mapstructure:"cookie_secret" yaml:"cookie_secret,omitempty"`
	CookieDomain   string        `mapstructure:"cookie_domain" yaml:"cookie_domain,omitempty"`
	CookieSecure   bool          `mapstructure:"cookie_secure" yaml:"cookie_secure,omitempty"`
	CookieHTTPOnly bool          `mapstructure:"cookie_http_only" yaml:"cookie_http_only,omitempty"`
	CookieExpire   time.Duration `mapstructure:"cookie_expire" yaml:"cookie_expire,omitempty"`

	// Identity provider configuration variables as specified by RFC6749
	// https://openid.net/specs/openid-connect-basic-1_0.html#RFC6749
	ClientID       string   `mapstructure:"idp_client_id" yaml:"idp_client_id,omitempty"`
	ClientSecret   string   `mapstructure:"idp_client_secret" yaml:"idp_client_secret,omitempty"`
	Provider       string   `mapstructure:"idp_provider" yaml:"idp_provider,omitempty"`
	ProviderURL    string   `mapstructure:"idp_provider_url" yaml:"idp_provider_url,omitempty"`
	Scopes         []string `mapstructure:"idp_scopes" yaml:"idp_scopes,omitempty"`
	ServiceAccount string   `mapstructure:"idp_service_account" yaml:"idp_service_account,omitempty"`
	// Identity provider refresh directory interval/timeout settings.
	RefreshDirectoryTimeout  time.Duration `mapstructure:"idp_refresh_directory_timeout" yaml:"idp_refresh_directory_timeout,omitempty"`
	RefreshDirectoryInterval time.Duration `mapstructure:"idp_refresh_directory_interval" yaml:"idp_refresh_directory_interval,omitempty"`
	QPS                      float64       `mapstructure:"idp_qps" yaml:"idp_qps"`

	// RequestParams are custom request params added to the signin request as
	// part of an Oauth2 code flow.
	//
	// https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml
	// https://openid.net/specs/openid-connect-basic-1_0.html#RequestParameters
	RequestParams map[string]string `mapstructure:"idp_request_params" yaml:"idp_request_params,omitempty"`

	// AuthorizeURL is the routable destination of the authorize service's
	// gRPC endpoint. NOTE: As many load balancers do not support
	// externally routed gRPC so this may be an internal location.
	AuthorizeURLString string   `mapstructure:"authorize_service_url" yaml:"authorize_service_url,omitempty"`
	AuthorizeURL       *url.URL `yaml:",omitempty"`

	// Settings to enable custom behind-the-ingress service communication
	OverrideCertificateName string `mapstructure:"override_certificate_name" yaml:"override_certificate_name,omitempty"`
	CA                      string `mapstructure:"certificate_authority" yaml:"certificate_authority,omitempty"`
	CAFile                  string `mapstructure:"certificate_authority_file" yaml:"certificate_authority_file,omitempty"`

	// SigningKey is the private key used to add a JWT-signature to upstream requests.
	// https://www.pomerium.io/docs/topics/getting-users-identity.html
	SigningKey          string `mapstructure:"signing_key" yaml:"signing_key,omitempty"`
	SigningKeyAlgorithm string `mapstructure:"signing_key_algorithm" yaml:"signing_key_algorithm,omitempty"`

	// Headers to set on all proxied requests. Add a 'disable' key map to turn off.
	HeadersEnv string            `yaml:",omitempty"`
	Headers    map[string]string `yaml:",omitempty"`

	// List of JWT claims to insert as x-pomerium-claim-* headers on proxied requests
	JWTClaimsHeaders []string `mapstructure:"jwt_claims_headers" yaml:"jwt_claims_headers,omitempty"`

	// RefreshCooldown limits the rate a user can refresh her session
	RefreshCooldown time.Duration `mapstructure:"refresh_cooldown" yaml:"refresh_cooldown,omitempty"`

	DefaultUpstreamTimeout time.Duration `mapstructure:"default_upstream_timeout" yaml:"default_upstream_timeout,omitempty"`

	// Address/Port to bind to for prometheus metrics
	MetricsAddr string `mapstructure:"metrics_address" yaml:"metrics_address,omitempty"`

	// Tracing shared settings
	TracingProvider   string  `mapstructure:"tracing_provider" yaml:"tracing_provider,omitempty"`
	TracingSampleRate float64 `mapstructure:"tracing_sample_rate" yaml:"tracing_sample_rate,omitempty"`

	// Datadog tracing address
	TracingDatadogAddress string `mapstructure:"tracing_datadog_address" yaml:"tracing_datadog_address,omitempty"`

	//  Jaeger
	//
	// CollectorEndpoint is the full url to the Jaeger HTTP Thrift collector.
	// For example, http://localhost:14268/api/traces
	TracingJaegerCollectorEndpoint string `mapstructure:"tracing_jaeger_collector_endpoint" yaml:"tracing_jaeger_collector_endpoint,omitempty"`
	// AgentEndpoint instructs exporter to send spans to jaeger-agent at this address.
	// For example, localhost:6831.

	// Zipkin
	//
	// ZipkinEndpoint configures the zipkin collector URI
	// Example: http://zipkin:9411/api/v2/spans
	TracingJaegerAgentEndpoint string `mapstructure:"tracing_jaeger_agent_endpoint" yaml:"tracing_jaeger_agent_endpoint,omitempty"`
	ZipkinEndpoint             string `mapstructure:"tracing_zipkin_endpoint" yaml:"tracing_zipkin_endpoint"`

	// GRPC Service Settings

	// GRPCAddr specifies the host and port on which the server should serve
	// gRPC requests. If running in all-in-one mode, ":5443" (localhost:5443) is used.
	GRPCAddr string `mapstructure:"grpc_address" yaml:"grpc_address,omitempty"`

	// GRPCInsecure disables transport security.
	// If running in all-in-one mode, defaults to true.
	GRPCInsecure bool `mapstructure:"grpc_insecure" yaml:"grpc_insecure,omitempty"`

	GRPCClientTimeout       time.Duration `mapstructure:"grpc_client_timeout" yaml:"grpc_client_timeout,omitempty"`
	GRPCClientDNSRoundRobin bool          `mapstructure:"grpc_client_dns_roundrobin" yaml:"grpc_client_dns_roundrobin,omitempty"`

	// GRPCServerMaxConnectionAge sets MaxConnectionAge in the grpc ServerParameters used to create GRPC Services
	GRPCServerMaxConnectionAge time.Duration `mapstructure:"grpc_server_max_connection_age" yaml:"grpc_server_max_connection_age,omitempty"`
	// GRPCServerMaxConnectionAgeGrace sets MaxConnectionAgeGrace in the grpc ServerParameters used to create GRPC Services
	GRPCServerMaxConnectionAgeGrace time.Duration `mapstructure:"grpc_server_max_connection_age_grace,omitempty" yaml:"grpc_server_max_connection_age_grace,omitempty"` //nolint: lll

	// ForwardAuthEndpoint allows for a given route to be used as a forward-auth
	// endpoint instead of a reverse proxy. Some third-party proxies that do not
	// have rich access control capabilities (nginx, envoy, ambassador, traefik)
	// allow you to delegate and authenticate each request to your website
	// with an external server or service. Pomerium can be configured to accept
	// these requests with this switch
	ForwardAuthURLString string   `mapstructure:"forward_auth_url" yaml:"forward_auth_url,omitempty"`
	ForwardAuthURL       *url.URL `yaml:",omitempty"`

	// DataBrokerURL is the routable destination of the databroker service's gRPC endpiont.
	DataBrokerURLString string   `mapstructure:"databroker_service_url" yaml:"databroker_service_url,omitempty"`
	DataBrokerURL       *url.URL `yaml:",omitempty"`
	// DataBrokerStorageType is the storage backend type that databroker will use.
	// Supported type: memory, redis
	DataBrokerStorageType string `mapstructure:"databroker_storage_type" yaml:"databroker_storage_type,omitempty"`
	// DataBrokerStorageConnectionString is the data source name for storage backend.
	DataBrokerStorageConnectionString string `mapstructure:"databroker_storage_connection_string" yaml:"databroker_storage_connection_string,omitempty"`
	DataBrokerStorageCertFile         string `mapstructure:"databroker_storage_cert_file" yaml:"databroker_storage_cert_file,omitempty"`
	DataBrokerStorageCertKeyFile      string `mapstructure:"databroker_storage_key_file" yaml:"databroker_storage_key_file,omitempty"`
	DataBrokerStorageCAFile           string `mapstructure:"databroker_storage_ca_file" yaml:"databroker_storage_ca_file,omitempty"`
	DataBrokerStorageCertSkipVerify   bool   `mapstructure:"databroker_storage_tls_skip_verify" yaml:"databroker_storage_tls_skip_verify,omitempty"`

	DataBrokerCertificate *tls.Certificate `mapstructure:"-" yaml:"-"`

	// ClientCA is the base64-encoded certificate authority to validate client mTLS certificates against.
	ClientCA string `mapstructure:"client_ca" yaml:"client_ca,omitempty"`
	// ClientCAFile points to a file that contains the certificate authority to validate client mTLS certificates against.
	ClientCAFile string `mapstructure:"client_ca_file" yaml:"client_ca_file,omitempty"`

	// GoogleCloudServerlessAuthenticationServiceAccount is the service account to use for GCP serverless authentication.
	// If unset, the GCP metadata server will be used to query for identity tokens.
	GoogleCloudServerlessAuthenticationServiceAccount string `mapstructure:"google_cloud_serverless_authentication_service_account" yaml:"google_cloud_serverless_authentication_service_account,omitempty"` //nolint

	// UseProxyProtocol configures the HTTP listener to require the HAProxy proxy protocol (either v1 or v2) on incoming requests.
	UseProxyProtocol bool `mapstructure:"require_proxy_protocol" yaml:"require_proxy_protocol,omitempty" json:"require_proxy_protocol,omitempty"`

	viper *viper.Viper

	AutocertOptions `mapstructure:",squash" yaml:",inline"`

	// SkipXffAppend instructs proxy not to append its IP address to x-forwarded-for header.
	// see https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers.html?highlight=skip_xff_append#x-forwarded-for
	SkipXffAppend bool `mapstructure:"skip_xff_append" yaml:"skip_xff_append,omitempty" json:"skip_xff_append,omitempty"`
}

type certificateFilePair struct {
	// CertFile and KeyFile is the x509 certificate used to hydrate TLSCertificate
	CertFile string `mapstructure:"cert" yaml:"cert,omitempty"`
	KeyFile  string `mapstructure:"key" yaml:"key,omitempty"`
}

// DefaultOptions are the default configuration options for pomerium
var defaultOptions = Options{
	Debug:                  false,
	LogLevel:               "info",
	Services:               "all",
	CookieHTTPOnly:         true,
	CookieSecure:           true,
	CookieExpire:           14 * time.Hour,
	CookieName:             "_pomerium",
	DefaultUpstreamTimeout: 30 * time.Second,
	Headers: map[string]string{
		"X-Frame-Options":           "SAMEORIGIN",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
	},
	Addr:                            ":443",
	ReadTimeout:                     30 * time.Second,
	WriteTimeout:                    0, // support streaming by default
	IdleTimeout:                     5 * time.Minute,
	RefreshCooldown:                 5 * time.Minute,
	GRPCAddr:                        ":443",
	GRPCClientTimeout:               10 * time.Second, // Try to withstand transient service failures for a single request
	GRPCClientDNSRoundRobin:         true,
	GRPCServerMaxConnectionAge:      5 * time.Minute,
	GRPCServerMaxConnectionAgeGrace: 5 * time.Minute,
	AuthenticateCallbackPath:        "/oauth2/callback",
	TracingSampleRate:               0.0001,
	RefreshDirectoryInterval:        10 * time.Minute,
	RefreshDirectoryTimeout:         1 * time.Minute,
	QPS:                             1.0,

	AutocertOptions: AutocertOptions{
		Folder: dataDir(),
	},
	DataBrokerStorageType: "memory",
	SkipXffAppend:         false,
}

// NewDefaultOptions returns a copy the default options. It's the caller's
// responsibility to do a follow up Validate call.
func NewDefaultOptions() *Options {
	newOpts := defaultOptions
	newOpts.viper = viper.New()
	return &newOpts
}

// newOptionsFromConfig builds the main binary's configuration options by parsing
// environmental variables and config file
func newOptionsFromConfig(configFile string) (*Options, error) {
	o, err := optionsFromViper(configFile)
	if err != nil {
		return nil, fmt.Errorf("config: options from config file %q: %w", configFile, err)
	}
	serviceName := telemetry.ServiceName(o.Services)
	metrics.AddPolicyCountCallback(serviceName, func() int64 {
		return int64(len(o.GetAllPolicies()))
	})

	metrics.SetConfigChecksum(serviceName, o.Checksum())

	return o, nil
}

func optionsFromViper(configFile string) (*Options, error) {
	// start a copy of the default options
	o := NewDefaultOptions()
	v := o.viper
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

	if err := v.Unmarshal(o, viperPolicyHooks); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// This is necessary because v.Unmarshal will overwrite .viper field.
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
	if err := o.viper.UnmarshalKey("policy", &policies, viperPolicyHooks); err != nil {
		return err
	}
	if len(policies) != 0 {
		o.Policies = policies
	}
	// Finish initializing policies
	for i := range o.Policies {
		p := &o.Policies[i]
		if err := p.Validate(); err != nil {
			return err
		}
	}
	for i := range o.AdditionalPolicies {
		p := &o.AdditionalPolicies[i]
		if err := p.Validate(); err != nil {
			return err
		}
	}
	return nil
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
		if err := o.viper.UnmarshalKey("headers", &headers); err != nil {
			return fmt.Errorf("header %s failed to parse: %w", o.viper.Get("headers"), err)
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
	err := v.BindEnv("Policy", "POLICY")
	if err != nil {
		return fmt.Errorf("failed to bind field 'Policy' to env var 'POLICY': %w", err)
	}
	err = v.BindEnv("HeadersEnv", "HEADERS")
	if err != nil {
		return fmt.Errorf("failed to bind field 'HeadersEnv' to env var 'HEADERS': %w", err)
	}
	// autocert options
	ao := reflect.TypeOf(o.AutocertOptions)
	for i := 0; i < ao.NumField(); i++ {
		field := ao.Field(i)
		envName := field.Tag.Get(tagName)
		err := v.BindEnv(envName)
		if err != nil {
			return fmt.Errorf("failed to bind field '%s' to env var '%s': %w", field.Name, envName, err)
		}
	}

	return nil
}

// Validate ensures the Options fields are valid, and hydrated.
func (o *Options) Validate() error {
	if !IsValidService(o.Services) {
		return fmt.Errorf("config: %s is an invalid service type", o.Services)
	}

	if IsAll(o.Services) {
		// mutual auth between services on the same host can be generated at runtime
		if o.SharedKey == "" && o.DataBrokerStorageType == StorageInMemoryName {
			o.SharedKey = cryptutil.NewBase64Key()
		}
		// in all in one mode we are running just over the local socket
		o.GRPCInsecure = true
		// to avoid port collision when running on localhost
		if o.GRPCAddr == defaultOptions.GRPCAddr {
			o.GRPCAddr = DefaultAlternativeAddr
		}
		// and we can set the corresponding client
		if o.AuthorizeURLString == "" {
			o.AuthorizeURLString = "http://127.0.0.1" + DefaultAlternativeAddr
		}
		if o.DataBrokerURLString == "" {
			o.DataBrokerURLString = "http://127.0.0.1" + DefaultAlternativeAddr
		}
	}

	switch o.DataBrokerStorageType {
	case StorageInMemoryName:
	case StorageRedisName:
		if o.DataBrokerStorageConnectionString == "" {
			return errors.New("config: missing databroker storage backend dsn")
		}
	default:
		return errors.New("config: unknown databroker storage backend type")
	}

	if IsAuthorize(o.Services) || IsDataBroker(o.Services) {
		// if authorize is set, we don't really need a http server
		// but we'll still set one up incase the user wants to use
		// the HTTP health check api
		if o.Addr == o.GRPCAddr {
			o.Addr = DefaultAlternativeAddr
			log.Warn().Str("Addr", o.Addr).Str("GRPCAddr", o.Addr).Msg("config: default http handler changed")
		}
	}

	if o.SharedKey == "" {
		return errors.New("config: shared-key cannot be empty")
	}

	if o.SharedKey != strings.TrimSpace(o.SharedKey) {
		return errors.New("config: shared-key contains whitespace")
	}

	if o.AuthenticateURLString != "" {
		u, err := urlutil.ParseAndValidateURL(o.AuthenticateURLString)
		if err != nil {
			return fmt.Errorf("config: bad authenticate-url %s : %w", o.AuthenticateURLString, err)
		}
		o.AuthenticateURL = u
	}

	if o.SignOutRedirectURLString != "" {
		u, err := urlutil.ParseAndValidateURL(o.SignOutRedirectURLString)
		if err != nil {
			return fmt.Errorf("config: bad signout-redirect-url %s : %w", o.SignOutRedirectURLString, err)
		}
		o.SignOutRedirectURL = u
	}

	if o.AuthorizeURLString != "" {
		u, err := urlutil.ParseAndValidateURL(o.AuthorizeURLString)
		if err != nil {
			return fmt.Errorf("config: bad authorize-url %s : %w", o.AuthorizeURLString, err)
		}
		o.AuthorizeURL = u
	}

	if o.DataBrokerURLString != "" {
		u, err := urlutil.ParseAndValidateURL(o.DataBrokerURLString)
		if err != nil {
			return fmt.Errorf("config: bad databroker service url %s : %w", o.DataBrokerURLString, err)
		}
		o.DataBrokerURL = u
	}

	if o.ForwardAuthURLString != "" {
		u, err := urlutil.ParseAndValidateURL(o.ForwardAuthURLString)
		if err != nil {
			return fmt.Errorf("config: bad forward-auth-url %s : %w", o.ForwardAuthURLString, err)
		}
		o.ForwardAuthURL = u
	}

	if o.PolicyFile != "" {
		return errors.New("config: policy file setting is deprecated")
	}
	if err := o.parsePolicy(); err != nil {
		return fmt.Errorf("config: failed to parse policy: %w", err)
	}

	if err := o.parseHeaders(); err != nil {
		return fmt.Errorf("config: failed to parse headers: %w", err)
	}

	if _, disable := o.Headers[DisableHeaderKey]; disable {
		o.Headers = make(map[string]string)
	}

	if o.Cert != "" || o.Key != "" {
		cert, err := cryptutil.CertificateFromBase64(o.Cert, o.Key)
		if err != nil {
			return fmt.Errorf("config: bad cert base64 %w", err)
		}
		o.Certificates = append(o.Certificates, *cert)
	}

	for _, c := range o.CertificateFiles {
		cert, err := cryptutil.CertificateFromBase64(c.CertFile, c.KeyFile)
		if err != nil {
			cert, err = cryptutil.CertificateFromFile(c.CertFile, c.KeyFile)
		}
		if err != nil {
			return fmt.Errorf("config: bad cert entry, base64 or file reference invalid. %w", err)
		}
		o.Certificates = append(o.Certificates, *cert)
	}

	if o.CertFile != "" || o.KeyFile != "" {
		cert, err := cryptutil.CertificateFromFile(o.CertFile, o.KeyFile)
		if err != nil {
			return fmt.Errorf("config: bad cert file %w", err)
		}
		o.Certificates = append(o.Certificates, *cert)
	}

	if o.DataBrokerStorageCertFile != "" || o.DataBrokerStorageCertKeyFile != "" {
		cert, err := cryptutil.CertificateFromFile(o.DataBrokerStorageCertFile, o.DataBrokerStorageCertKeyFile)
		if err != nil {
			return fmt.Errorf("config: bad databroker cert file %w", err)
		}
		o.DataBrokerCertificate = cert
	}

	if o.DataBrokerStorageCAFile != "" {
		if _, err := os.Stat(o.DataBrokerStorageCAFile); err != nil {
			return fmt.Errorf("config: bad databroker ca file: %w", err)
		}
	}

	if o.ClientCA != "" {
		if _, err := base64.StdEncoding.DecodeString(o.ClientCA); err != nil {
			return fmt.Errorf("config: bad client ca base64: %w", err)
		}
	}

	if o.ClientCAFile != "" {
		bs, err := ioutil.ReadFile(o.ClientCAFile)
		if err != nil {
			return fmt.Errorf("config: bad client ca file: %w", err)
		}
		o.ClientCA = base64.StdEncoding.EncodeToString(bs)
	}

	// if no service account was defined, there should not be any policies that
	// assert group membership (except for azure which can be derived from the client
	// id, secret and provider url)
	if o.ServiceAccount == "" && o.Provider != "azure" {
		for _, p := range o.GetAllPolicies() {
			if len(p.AllowedGroups) != 0 {
				return fmt.Errorf("config: `allowed_groups` requires `idp_service_account`")
			}
		}
	}

	// if we are using google provider, default to using ServiceAccount for
	// GoogleCloudServerlessAuthenticationServiceAccount
	if o.Provider == "google" && o.GoogleCloudServerlessAuthenticationServiceAccount == "" {
		o.GoogleCloudServerlessAuthenticationServiceAccount = o.ServiceAccount
		log.Info().Msg("defaulting to idp_service_account for google_cloud_serverless_authentication_service_account")
	}

	// strip quotes from redirect address (#811)
	o.HTTPRedirectAddr = strings.Trim(o.HTTPRedirectAddr, `"'`)

	// sort the certificates so we get a consistent hash
	sort.Slice(o.Certificates, func(i, j int) bool {
		return compareByteSliceSlice(o.Certificates[i].Certificate, o.Certificates[j].Certificate) < 0
	})

	if !o.InsecureServer && len(o.Certificates) == 0 && !o.AutocertOptions.Enable {
		return fmt.Errorf("config: server must be run with `autocert`, " +
			"`insecure_server` or manually provided certificates to start")
	}

	switch o.Provider {
	case azure.Name, github.Name, gitlab.Name, google.Name, okta.Name, onelogin.Name:
		if len(o.Scopes) > 0 {
			log.Warn().Msg(idpCustomScopesWarnMsg)
		}
	default:
	}

	if o.QPS < 1.0 {
		o.QPS = 1.0
	}

	if err := ValidateDNSLookupFamily(o.DNSLookupFamily); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	return nil
}

// GetAuthenticateURL returns the AuthenticateURL in the options or 127.0.0.1.
func (o *Options) GetAuthenticateURL() (*url.URL, error) {
	if o != nil && o.AuthenticateURL != nil {
		return o.AuthenticateURL, nil
	}
	return url.Parse("https://127.0.0.1")
}

// GetAuthorizeURL returns the AuthorizeURL in the options or 127.0.0.1:5443.
func (o *Options) GetAuthorizeURL() (*url.URL, error) {
	if o != nil && o.AuthorizeURL != nil {
		return o.AuthorizeURL, nil
	}
	return url.Parse("http://127.0.0.1" + DefaultAlternativeAddr)
}

// GetDataBrokerURL returns the DataBrokerURL in the options or 127.0.0.1:5443.
func (o *Options) GetDataBrokerURL() (*url.URL, error) {
	if o != nil && o.DataBrokerURL != nil {
		return o.DataBrokerURL, nil
	}
	return url.Parse("http://127.0.0.1" + DefaultAlternativeAddr)
}

// GetForwardAuthURL returns the ForwardAuthURL in the options or 127.0.0.1.
func (o *Options) GetForwardAuthURL() (*url.URL, error) {
	if o != nil && o.ForwardAuthURL != nil {
		return o.ForwardAuthURL, nil
	}
	return url.Parse("https://127.0.0.1")
}

// GetOauthOptions gets the oauth.Options for the given config options.
func (o *Options) GetOauthOptions() (oauth.Options, error) {
	redirectURL, err := o.GetAuthenticateURL()
	if err != nil {
		return oauth.Options{}, err
	}
	redirectURL = redirectURL.ResolveReference(&url.URL{
		Path: o.AuthenticateCallbackPath,
	})
	return oauth.Options{
		RedirectURL:    redirectURL,
		ProviderName:   o.Provider,
		ProviderURL:    o.ProviderURL,
		ClientID:       o.ClientID,
		ClientSecret:   o.ClientSecret,
		Scopes:         o.Scopes,
		ServiceAccount: o.ServiceAccount,
	}, nil
}

// GetAllPolicies gets all the policies in the options.
func (o *Options) GetAllPolicies() []Policy {
	if o == nil {
		return nil
	}
	policies := make([]Policy, 0, len(o.Policies)+len(o.AdditionalPolicies))
	policies = append(policies, o.Policies...)
	policies = append(policies, o.AdditionalPolicies...)
	return policies
}

// Checksum returns the checksum of the current options struct
func (o *Options) Checksum() uint64 {
	return hashutil.MustHash(o)
}

// ApplySettings modifies the config options using the given protobuf settings.
func (o *Options) ApplySettings(settings *config.Settings) {
	if settings == nil {
		return
	}

	if settings.Debug != nil {
		o.Debug = settings.GetDebug()
	}
	if settings.LogLevel != nil {
		o.LogLevel = settings.GetLogLevel()
	}
	if settings.ProxyLogLevel != nil {
		o.ProxyLogLevel = settings.GetProxyLogLevel()
	}
	if settings.SharedSecret != nil {
		o.SharedKey = settings.GetSharedSecret()
	}
	if settings.Services != nil {
		o.Services = settings.GetServices()
	}
	if settings.Address != nil {
		o.Addr = settings.GetAddress()
	}
	if settings.InsecureServer != nil {
		o.InsecureServer = settings.GetInsecureServer()
	}
	if settings.DnsLookupFamily != nil {
		o.DNSLookupFamily = settings.GetDnsLookupFamily()
	}
	for _, c := range settings.Certificates {
		cfp := certificateFilePair{
			CertFile: c.CertFile,
			KeyFile:  c.KeyFile,
		}
		if cfp.CertFile == "" {
			cfp.CertFile = base64.StdEncoding.EncodeToString(c.CertBytes)
		}
		if cfp.KeyFile == "" {
			cfp.KeyFile = base64.StdEncoding.EncodeToString(c.KeyBytes)
		}
		o.CertificateFiles = append(o.CertificateFiles, cfp)
	}
	if settings.HttpRedirectAddr != nil {
		o.HTTPRedirectAddr = settings.GetHttpRedirectAddr()
	}
	if settings.TimeoutRead != nil {
		o.ReadTimeout = settings.GetTimeoutRead().AsDuration()
	}
	if settings.TimeoutWrite != nil {
		o.WriteTimeout = settings.GetTimeoutWrite().AsDuration()
	}
	if settings.TimeoutIdle != nil {
		o.IdleTimeout = settings.GetTimeoutIdle().AsDuration()
	}
	if settings.AuthenticateServiceUrl != nil {
		o.AuthenticateURLString = settings.GetAuthenticateServiceUrl()
	}
	if settings.AuthenticateCallbackPath != nil {
		o.AuthenticateCallbackPath = settings.GetAuthenticateCallbackPath()
	}
	if settings.CookieName != nil {
		o.CookieName = settings.GetCookieName()
	}
	if settings.CookieSecret != nil {
		o.CookieSecret = settings.GetCookieSecret()
	}
	if settings.CookieDomain != nil {
		o.CookieDomain = settings.GetCookieDomain()
	}
	if settings.CookieSecure != nil {
		o.CookieSecure = settings.GetCookieSecure()
	}
	if settings.CookieHttpOnly != nil {
		o.CookieHTTPOnly = settings.GetCookieHttpOnly()
	}
	if settings.CookieExpire != nil {
		o.CookieExpire = settings.GetCookieExpire().AsDuration()
	}
	if settings.IdpClientId != nil {
		o.ClientID = settings.GetIdpClientId()
	}
	if settings.IdpClientSecret != nil {
		o.ClientSecret = settings.GetIdpClientSecret()
	}
	if settings.IdpProvider != nil {
		o.Provider = settings.GetIdpProvider()
	}
	if settings.IdpProviderUrl != nil {
		o.ProviderURL = settings.GetIdpProviderUrl()
	}
	if len(settings.Scopes) > 0 {
		o.Scopes = settings.Scopes
	}
	if settings.IdpServiceAccount != nil {
		o.ServiceAccount = settings.GetIdpServiceAccount()
	}
	if settings.IdpRefreshDirectoryTimeout != nil {
		o.RefreshDirectoryTimeout = settings.GetIdpRefreshDirectoryTimeout().AsDuration()
	}
	if settings.IdpRefreshDirectoryInterval != nil {
		o.RefreshDirectoryInterval = settings.GetIdpRefreshDirectoryInterval().AsDuration()
	}
	if settings.RequestParams != nil && len(settings.RequestParams) > 0 {
		o.RequestParams = settings.RequestParams
	}
	if settings.AuthorizeServiceUrl != nil {
		o.AuthorizeURLString = settings.GetAuthorizeServiceUrl()
	}
	if settings.OverrideCertificateName != nil {
		o.OverrideCertificateName = settings.GetOverrideCertificateName()
	}
	if settings.CertificateAuthority != nil {
		o.CA = settings.GetCertificateAuthority()
	}
	if settings.CertificateAuthorityFile != nil {
		o.CAFile = settings.GetCertificateAuthorityFile()
	}
	if settings.SigningKey != nil {
		o.SigningKey = settings.GetSigningKey()
	}
	if settings.SigningKeyAlgorithm != nil {
		o.SigningKeyAlgorithm = settings.GetSigningKeyAlgorithm()
	}
	if len(settings.JwtClaimsHeaders) > 0 {
		o.JWTClaimsHeaders = settings.GetJwtClaimsHeaders()
	}
	if settings.RefreshCooldown != nil {
		o.RefreshCooldown = settings.GetRefreshCooldown().AsDuration()
	}
	if settings.DefaultUpstreamTimeout != nil {
		o.DefaultUpstreamTimeout = settings.GetDefaultUpstreamTimeout().AsDuration()
	}
	if settings.MetricsAddress != nil {
		o.MetricsAddr = settings.GetMetricsAddress()
	}
	if settings.TracingProvider != nil {
		o.TracingProvider = settings.GetTracingProvider()
	}
	if settings.TracingSampleRate != nil {
		o.TracingSampleRate = settings.GetTracingSampleRate()
	}
	if settings.TracingJaegerCollectorEndpoint != nil {
		o.TracingJaegerCollectorEndpoint = settings.GetTracingJaegerCollectorEndpoint()
	}
	if settings.TracingJaegerAgentEndpoint != nil {
		o.TracingJaegerAgentEndpoint = settings.GetTracingJaegerAgentEndpoint()
	}
	if settings.TracingZipkinEndpoint != nil {
		o.ZipkinEndpoint = settings.GetTracingZipkinEndpoint()
	}
	if settings.GrpcAddress != nil {
		o.GRPCAddr = settings.GetGrpcAddress()
	}
	if settings.GrpcInsecure != nil {
		o.GRPCInsecure = settings.GetGrpcInsecure()
	}
	if settings.GrpcServerMaxConnectionAge != nil {
		o.GRPCServerMaxConnectionAge = settings.GetGrpcServerMaxConnectionAge().AsDuration()
	}
	if settings.GrpcServerMaxConnectionAgeGrace != nil {
		o.GRPCServerMaxConnectionAgeGrace = settings.GetGrpcServerMaxConnectionAgeGrace().AsDuration()
	}
	if settings.ForwardAuthUrl != nil {
		o.ForwardAuthURLString = settings.GetForwardAuthUrl()
	}
	if settings.DatabrokerServiceUrl != nil {
		o.DataBrokerURLString = settings.GetDatabrokerServiceUrl()
	}
	if settings.ClientCa != nil {
		o.ClientCA = settings.GetClientCa()
	}
	if settings.ClientCaFile != nil {
		o.ClientCAFile = settings.GetClientCaFile()
	}
	if settings.GoogleCloudServerlessAuthenticationServiceAccount != nil {
		o.GoogleCloudServerlessAuthenticationServiceAccount = settings.GetGoogleCloudServerlessAuthenticationServiceAccount()
	}
	if settings.Autocert != nil {
		o.AutocertOptions.Enable = settings.GetAutocert()
	}
	if settings.AutocertUseStaging != nil {
		o.AutocertOptions.UseStaging = settings.GetAutocertUseStaging()
	}
	if settings.AutocertMustStaple != nil {
		o.AutocertOptions.MustStaple = settings.GetAutocertMustStaple()
	}
	if settings.AutocertDir != nil {
		o.AutocertOptions.Folder = settings.GetAutocertDir()
	}
	if settings.SkipXffAppend != nil {
		o.SkipXffAppend = settings.GetSkipXffAppend()
	}
}

// handleConfigUpdate takes configuration file, an existing options struct, and
// returns new options if any change is detected. If no change was detected, the
// existing option will be returned.
func handleConfigUpdate(configFile string, opt *Options) *Options {
	serviceName := telemetry.ServiceName(opt.Services)

	newOpt, err := newOptionsFromConfig(configFile)
	if err != nil {
		log.Error().Err(err).Msg("config: could not reload configuration")
		metrics.SetConfigInfo(serviceName, false)
		return opt
	}
	optChecksum := opt.Checksum()
	newOptChecksum := newOpt.Checksum()

	log.Debug().Str("old-checksum", fmt.Sprintf("%x", optChecksum)).Str("new-checksum", fmt.Sprintf("%x", newOptChecksum)).Msg("config: checksum change")

	if newOptChecksum == optChecksum {
		log.Debug().Msg("config: loaded configuration has not changed")
		return opt
	}

	return newOpt
}

func dataDir() string {
	homeDir, _ := os.UserHomeDir()
	if homeDir == "" {
		homeDir = "."
	}
	baseDir := filepath.Join(homeDir, ".local", "share")
	if xdgData := os.Getenv("XDG_DATA_HOME"); xdgData != "" {
		baseDir = xdgData
	}
	return filepath.Join(baseDir, "pomerium")
}

func compareByteSliceSlice(a, b [][]byte) int {
	sz := min(len(a), len(b))
	for i := 0; i < sz; i++ {
		switch bytes.Compare(a[i], b[i]) {
		case -1:
			return -1
		case 1:
			return 1
		}
	}

	switch {
	case len(a) < len(b):
		return -1
	case len(b) < len(a):
		return 1
	default:
		return 0
	}
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// AtomicOptions are Options that can be access atomically.
type AtomicOptions struct {
	value atomic.Value
}

// NewAtomicOptions creates a new AtomicOptions.
func NewAtomicOptions() *AtomicOptions {
	ao := new(AtomicOptions)
	ao.Store(new(Options))
	return ao
}

// Load loads the options.
func (a *AtomicOptions) Load() *Options {
	return a.value.Load().(*Options)
}

// Store stores the options.
func (a *AtomicOptions) Store(options *Options) {
	a.value.Store(options)
}
