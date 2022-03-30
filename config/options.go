package config

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"github.com/volatiletech/null/v9"

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

// The randomSharedKey is used if no shared key is supplied in all-in-one mode.
var randomSharedKey = cryptutil.NewBase64Key()

// Options are the global environmental flags used to set up pomerium's services.
// Use NewXXXOptions() methods for a safely initialized data structure.
type Options struct {
	// InstallationID is used to indicate a unique installation of pomerium. Useful for telemetry.
	InstallationID string `mapstructure:"installation_id" yaml:"installation_id,omitempty"`

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
	Routes     []Policy `mapstructure:"routes"`

	// AdditionalPolicies are any additional policies added to the options.
	AdditionalPolicies []Policy `yaml:"-"`

	// AuthenticateURL represents the externally accessible http endpoints
	// used for authentication requests and callbacks
	AuthenticateURLString         string `mapstructure:"authenticate_service_url" yaml:"authenticate_service_url,omitempty"`
	AuthenticateInternalURLString string `mapstructure:"authenticate_internal_service_url" yaml:"authenticate_internal_service_url,omitempty"`
	// SignOutRedirectURL represents the url that  user will be redirected to after signing out.
	SignOutRedirectURLString string `mapstructure:"signout_redirect_url" yaml:"signout_redirect_url,omitempty"`

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

	// AuthorizeURLString is the routable destination of the authorize service's
	// gRPC endpoint. NOTE: As many load balancers do not support
	// externally routed gRPC so this may be an internal location.
	AuthorizeURLString         string   `mapstructure:"authorize_service_url" yaml:"authorize_service_url,omitempty"`
	AuthorizeURLStrings        []string `mapstructure:"authorize_service_urls" yaml:"authorize_service_urls,omitempty"`
	AuthorizeInternalURLString string   `mapstructure:"authorize_internal_service_url" yaml:"authorize_internal_service_url,omitempty"`

	// Settings to enable custom behind-the-ingress service communication
	OverrideCertificateName string `mapstructure:"override_certificate_name" yaml:"override_certificate_name,omitempty"`
	CA                      string `mapstructure:"certificate_authority" yaml:"certificate_authority,omitempty"`
	CAFile                  string `mapstructure:"certificate_authority_file" yaml:"certificate_authority_file,omitempty"`

	// SigningKey is the private key used to add a JWT-signature to upstream requests.
	// https://www.pomerium.io/docs/topics/getting-users-identity.html
	SigningKey string `mapstructure:"signing_key" yaml:"signing_key,omitempty"`

	HeadersEnv string `yaml:",omitempty"`
	// SetResponseHeaders to set on all proxied requests. Add a 'disable' key map to turn off.
	SetResponseHeaders map[string]string `yaml:",omitempty"`

	// List of JWT claims to insert as x-pomerium-claim-* headers on proxied requests
	JWTClaimsHeaders JWTClaimHeaders `mapstructure:"jwt_claims_headers" yaml:"jwt_claims_headers,omitempty"`

	DefaultUpstreamTimeout time.Duration `mapstructure:"default_upstream_timeout" yaml:"default_upstream_timeout,omitempty"`

	// Address/Port to bind to for prometheus metrics
	MetricsAddr string `mapstructure:"metrics_address" yaml:"metrics_address,omitempty"`
	// - require basic auth for prometheus metrics, base64 encoded user:pass string
	MetricsBasicAuth string `mapstructure:"metrics_basic_auth" yaml:"metrics_basic_auth,omitempty"`
	// - TLS options
	MetricsCertificate        string `mapstructure:"metrics_certificate" yaml:"metrics_certificate,omitempty"`
	MetricsCertificateKey     string `mapstructure:"metrics_certificate_key" yaml:"metrics_certificate_key,omitempty"`
	MetricsCertificateFile    string `mapstructure:"metrics_certificate_file" yaml:"metrics_certificate_file,omitempty"`
	MetricsCertificateKeyFile string `mapstructure:"metrics_certificate_key_file" yaml:"metrics_certificate_key_file,omitempty"`
	MetricsClientCA           string `mapstructure:"metrics_client_ca" yaml:"metrics_client_ca,omitempty"`
	MetricsClientCAFile       string `mapstructure:"metrics_client_ca_file" yaml:"metrics_client_ca_file,omitempty"`

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
	TracingJaegerAgentEndpoint string `mapstructure:"tracing_jaeger_agent_endpoint" yaml:"tracing_jaeger_agent_endpoint,omitempty"`

	// Zipkin
	//
	// ZipkinEndpoint configures the zipkin collector URI
	// Example: http://zipkin:9411/api/v2/spans
	ZipkinEndpoint string `mapstructure:"tracing_zipkin_endpoint" yaml:"tracing_zipkin_endpoint"`

	// GRPC Service Settings

	// GRPCAddr specifies the host and port on which the server should serve
	// gRPC requests. If running in all-in-one mode, ":5443" (localhost:5443) is used.
	GRPCAddr string `mapstructure:"grpc_address" yaml:"grpc_address,omitempty"`

	// GRPCInsecure disables transport security.
	// If running in all-in-one mode, defaults to true.
	GRPCInsecure bool `mapstructure:"grpc_insecure" yaml:"grpc_insecure,omitempty"`

	GRPCClientTimeout       time.Duration `mapstructure:"grpc_client_timeout" yaml:"grpc_client_timeout,omitempty"`
	GRPCClientDNSRoundRobin bool          `mapstructure:"grpc_client_dns_roundrobin" yaml:"grpc_client_dns_roundrobin,omitempty"`

	// ForwardAuthEndpoint allows for a given route to be used as a forward-auth
	// endpoint instead of a reverse proxy. Some third-party proxies that do not
	// have rich access control capabilities (nginx, envoy, ambassador, traefik)
	// allow you to delegate and authenticate each request to your website
	// with an external server or service. Pomerium can be configured to accept
	// these requests with this switch
	ForwardAuthURLString string `mapstructure:"forward_auth_url" yaml:"forward_auth_url,omitempty"`

	// DataBrokerURLString is the routable destination of the databroker service's gRPC endpiont.
	DataBrokerURLString         string   `mapstructure:"databroker_service_url" yaml:"databroker_service_url,omitempty"`
	DataBrokerURLStrings        []string `mapstructure:"databroker_service_urls" yaml:"databroker_service_urls,omitempty"`
	DataBrokerInternalURLString string   `mapstructure:"databroker_internal_service_url" yaml:"databroker_internal_service_url,omitempty"`
	// DataBrokerStorageType is the storage backend type that databroker will use.
	// Supported type: memory, redis
	DataBrokerStorageType string `mapstructure:"databroker_storage_type" yaml:"databroker_storage_type,omitempty"`
	// DataBrokerStorageConnectionString is the data source name for storage backend.
	DataBrokerStorageConnectionString string `mapstructure:"databroker_storage_connection_string" yaml:"databroker_storage_connection_string,omitempty"`
	DataBrokerStorageCertFile         string `mapstructure:"databroker_storage_cert_file" yaml:"databroker_storage_cert_file,omitempty"`
	DataBrokerStorageCertKeyFile      string `mapstructure:"databroker_storage_key_file" yaml:"databroker_storage_key_file,omitempty"`
	DataBrokerStorageCAFile           string `mapstructure:"databroker_storage_ca_file" yaml:"databroker_storage_ca_file,omitempty"`
	DataBrokerStorageCertSkipVerify   bool   `mapstructure:"databroker_storage_tls_skip_verify" yaml:"databroker_storage_tls_skip_verify,omitempty"`

	// ClientCA is the base64-encoded certificate authority to validate client mTLS certificates against.
	ClientCA string `mapstructure:"client_ca" yaml:"client_ca,omitempty"`
	// ClientCAFile points to a file that contains the certificate authority to validate client mTLS certificates against.
	ClientCAFile string `mapstructure:"client_ca_file" yaml:"client_ca_file,omitempty"`
	// ClientCRL is the base64-encoded certificate revocation list for client mTLS certificates.
	ClientCRL string `mapstructure:"client_crl" yaml:"client_crl,omitempty"`
	// ClientCRLFile points to a file that contains the certificate revocation list for client mTLS certificates.
	ClientCRLFile string `mapstructure:"client_crl_file" yaml:"client_crl_file,omitempty"`

	// GoogleCloudServerlessAuthenticationServiceAccount is the service account to use for GCP serverless authentication.
	// If unset, the GCP metadata server will be used to query for identity tokens.
	GoogleCloudServerlessAuthenticationServiceAccount string `mapstructure:"google_cloud_serverless_authentication_service_account" yaml:"google_cloud_serverless_authentication_service_account,omitempty"` //nolint

	// UseProxyProtocol configures the HTTP listener to require the HAProxy proxy protocol (either v1 or v2) on incoming requests.
	UseProxyProtocol bool `mapstructure:"use_proxy_protocol" yaml:"use_proxy_protocol,omitempty" json:"use_proxy_protocol,omitempty"`

	viper *viper.Viper

	AutocertOptions `mapstructure:",squash" yaml:",inline"`

	// SkipXffAppend instructs proxy not to append its IP address to x-forwarded-for header.
	// see https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers.html?highlight=skip_xff_append#x-forwarded-for
	SkipXffAppend bool `mapstructure:"skip_xff_append" yaml:"skip_xff_append,omitempty" json:"skip_xff_append,omitempty"`
	// XffNumTrustedHops determines the trusted client address from x-forwarded-for addresses.
	// see https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers.html?highlight=xff_num_trusted_hops#x-forwarded-for
	XffNumTrustedHops uint32 `mapstructure:"xff_num_trusted_hops" yaml:"xff_num_trusted_hops,omitempty" json:"xff_num_trusted_hops,omitempty"`

	// Envoy bootstrap options. These do not support dynamic updates.
	EnvoyAdminAccessLogPath      string    `mapstructure:"envoy_admin_access_log_path" yaml:"envoy_admin_access_log_path"`
	EnvoyAdminProfilePath        string    `mapstructure:"envoy_admin_profile_path" yaml:"envoy_admin_profile_path"`
	EnvoyAdminAddress            string    `mapstructure:"envoy_admin_address" yaml:"envoy_admin_address"`
	EnvoyBindConfigSourceAddress string    `mapstructure:"envoy_bind_config_source_address" yaml:"envoy_bind_config_source_address,omitempty"`
	EnvoyBindConfigFreebind      null.Bool `mapstructure:"envoy_bind_config_freebind" yaml:"envoy_bind_config_freebind,omitempty"`

	// ProgrammaticRedirectDomainWhitelist restricts the allowed redirect URLs when using programmatic login.
	ProgrammaticRedirectDomainWhitelist []string `mapstructure:"programmatic_redirect_domain_whitelist" yaml:"programmatic_redirect_domain_whitelist,omitempty" json:"programmatic_redirect_domain_whitelist,omitempty"` //nolint

	// CodecType is the codec to use for downstream connections.
	CodecType CodecType `mapstructure:"codec_type" yaml:"codec_type"`

	AuditKey *PublicKeyEncryptionKeyOptions `mapstructure:"audit_key"`
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
	SetResponseHeaders: map[string]string{
		"X-Frame-Options":           "SAMEORIGIN",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
	},
	Addr:                     ":443",
	ReadTimeout:              30 * time.Second,
	WriteTimeout:             0, // support streaming by default
	IdleTimeout:              5 * time.Minute,
	GRPCAddr:                 ":443",
	GRPCClientTimeout:        10 * time.Second, // Try to withstand transient service failures for a single request
	GRPCClientDNSRoundRobin:  true,
	AuthenticateCallbackPath: "/oauth2/callback",
	TracingSampleRate:        0.0001,
	RefreshDirectoryInterval: 10 * time.Minute,
	RefreshDirectoryTimeout:  1 * time.Minute,
	QPS:                      1.0,

	AutocertOptions: AutocertOptions{
		Folder: dataDir(),
	},
	DataBrokerStorageType:               "memory",
	SkipXffAppend:                       false,
	XffNumTrustedHops:                   0,
	EnvoyAdminAccessLogPath:             os.DevNull,
	EnvoyAdminProfilePath:               os.DevNull,
	EnvoyAdminAddress:                   "127.0.0.1:9901",
	ProgrammaticRedirectDomainWhitelist: []string{"localhost"},
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

	var metadata mapstructure.Metadata
	if err := v.Unmarshal(o, ViperPolicyHooks, func(c *mapstructure.DecoderConfig) { c.Metadata = &metadata }); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	checkUnusedConfigFields(configFile, metadata.Unused)

	// This is necessary because v.Unmarshal will overwrite .viper field.
	o.viper = v

	if err := o.Validate(); err != nil {
		return nil, fmt.Errorf("validation error %w", err)
	}
	return o, nil
}

func checkUnusedConfigFields(configFile string, unused []string) {
	keys := make([]string, 0, len(unused))
	for _, k := range unused {
		if !strings.HasPrefix(k, "policy[") { // policy's embedded protobuf structs are decoded by separate hook and are unknown to mapstructure
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return
	}
	log.Warn(context.Background()).Str("config_file", configFile).Strs("keys", keys).Msg("config contained unknown keys that were ignored")
}

// parsePolicy initializes policy to the options from either base64 environmental
// variables or from a file
func (o *Options) parsePolicy() error {
	var policies []Policy
	if err := o.viper.UnmarshalKey("policy", &policies, ViperPolicyHooks); err != nil {
		return err
	}
	if len(policies) != 0 {
		o.Policies = policies
	}

	var routes []Policy
	if err := o.viper.UnmarshalKey("routes", &routes, ViperPolicyHooks); err != nil {
		return err
	}
	if len(routes) != 0 {
		o.Routes = routes
	}

	// Finish initializing policies
	for i := range o.Policies {
		p := &o.Policies[i]
		if err := p.Validate(); err != nil {
			return err
		}
	}
	for i := range o.Routes {
		p := &o.Routes[i]
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
func (o *Options) parseHeaders(ctx context.Context) error {
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
		o.SetResponseHeaders = headers
		return nil
	}

	if o.viperIsSet("set_response_headers") {
		if err := o.viper.UnmarshalKey("set_response_headers", &headers); err != nil {
			return fmt.Errorf("header %s failed to parse: %w", o.viper.Get("set_response_headers"), err)
		}
		o.SetResponseHeaders = headers
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
	ctx := context.TODO()
	if !IsValidService(o.Services) {
		return fmt.Errorf("config: %s is an invalid service type", o.Services)
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

	_, err := o.GetSharedKey()
	if err != nil {
		return fmt.Errorf("config: invalid shared secret: %w", err)
	}

	if o.AuthenticateURLString != "" {
		_, err := urlutil.ParseAndValidateURL(o.AuthenticateURLString)
		if err != nil {
			return fmt.Errorf("config: bad authenticate-url %s : %w", o.AuthenticateURLString, err)
		}
	}
	if o.AuthenticateInternalURLString != "" {
		_, err := urlutil.ParseAndValidateURL(o.AuthenticateInternalURLString)
		if err != nil {
			return fmt.Errorf("config: bad authenticate-internal-url %s : %w", o.AuthenticateInternalURLString, err)
		}
	}

	if o.SignOutRedirectURLString != "" {
		_, err := urlutil.ParseAndValidateURL(o.SignOutRedirectURLString)
		if err != nil {
			return fmt.Errorf("config: bad signout-redirect-url %s : %w", o.SignOutRedirectURLString, err)
		}
	}

	if o.AuthorizeURLString != "" {
		_, err := urlutil.ParseAndValidateURL(o.AuthorizeURLString)
		if err != nil {
			return fmt.Errorf("config: bad authorize-url %s : %w", o.AuthorizeURLString, err)
		}
	}
	if o.AuthorizeInternalURLString != "" {
		_, err := urlutil.ParseAndValidateURL(o.AuthorizeInternalURLString)
		if err != nil {
			return fmt.Errorf("config: bad authorize-internal-url %s : %w", o.AuthorizeInternalURLString, err)
		}
	}

	if o.DataBrokerURLString != "" {
		_, err := urlutil.ParseAndValidateURL(o.DataBrokerURLString)
		if err != nil {
			return fmt.Errorf("config: bad databroker service url %s : %w", o.DataBrokerURLString, err)
		}
	}
	if o.DataBrokerInternalURLString != "" {
		_, err := urlutil.ParseAndValidateURL(o.DataBrokerInternalURLString)
		if err != nil {
			return fmt.Errorf("config: bad databroker internal service url %s : %w", o.DataBrokerInternalURLString, err)
		}
	}

	if o.ForwardAuthURLString != "" {
		_, err := urlutil.ParseAndValidateURL(o.ForwardAuthURLString)
		if err != nil {
			return fmt.Errorf("config: bad forward-auth-url %s : %w", o.ForwardAuthURLString, err)
		}
	}

	if o.PolicyFile != "" {
		return errors.New("config: policy file setting is deprecated")
	}
	if err := o.parsePolicy(); err != nil {
		return fmt.Errorf("config: failed to parse policy: %w", err)
	}

	if err := o.parseHeaders(ctx); err != nil {
		return fmt.Errorf("config: failed to parse headers: %w", err)
	}

	hasCert := false

	if o.Cert != "" || o.Key != "" {
		_, err := cryptutil.CertificateFromBase64(o.Cert, o.Key)
		if err != nil {
			return fmt.Errorf("config: bad cert base64 %w", err)
		}
		hasCert = true
	}

	for _, c := range o.CertificateFiles {
		_, err := cryptutil.CertificateFromBase64(c.CertFile, c.KeyFile)
		if err != nil {
			_, err = cryptutil.CertificateFromFile(c.CertFile, c.KeyFile)
		}
		if err != nil {
			return fmt.Errorf("config: bad cert entry, base64 or file reference invalid. %w", err)
		}
		hasCert = true
	}

	if o.CertFile != "" || o.KeyFile != "" {
		_, err := cryptutil.CertificateFromFile(o.CertFile, o.KeyFile)
		if err != nil {
			return fmt.Errorf("config: bad cert file %w", err)
		}
		hasCert = true
	}

	if o.DataBrokerStorageCertFile != "" || o.DataBrokerStorageCertKeyFile != "" {
		_, err := cryptutil.CertificateFromFile(o.DataBrokerStorageCertFile, o.DataBrokerStorageCertKeyFile)
		if err != nil {
			return fmt.Errorf("config: bad databroker cert file %w", err)
		}
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
		_, err := os.ReadFile(o.ClientCAFile)
		if err != nil {
			return fmt.Errorf("config: bad client ca file: %w", err)
		}
	}

	if o.ClientCRL != "" {
		_, err = cryptutil.CRLFromBase64(o.ClientCRL)
		if err != nil {
			return fmt.Errorf("config: bad client crl base64: %w", err)
		}
	}

	if o.ClientCRLFile != "" {
		_, err = cryptutil.CRLFromFile(o.ClientCRLFile)
		if err != nil {
			return fmt.Errorf("config: bad client crl file: %w", err)
		}
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

	// strip quotes from redirect address (#811)
	o.HTTPRedirectAddr = strings.Trim(o.HTTPRedirectAddr, `"'`)

	if !o.InsecureServer && !hasCert && !o.AutocertOptions.Enable {
		log.Warn(ctx).Msg("neither `autocert`, " +
			"`insecure_server` or manually provided certificates were provided, server will be using a self-signed certificate")
	}

	switch o.Provider {
	case azure.Name, github.Name, gitlab.Name, google.Name, okta.Name, onelogin.Name:
		if len(o.Scopes) > 0 {
			log.Warn(ctx).Msg(idpCustomScopesWarnMsg)
		}
	default:
	}

	if err := ValidateDNSLookupFamily(o.DNSLookupFamily); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	if o.MetricsAddr != "" {
		if err := ValidateMetricsAddress(o.MetricsAddr); err != nil {
			return fmt.Errorf("config: invalid metrics_addr: %w", err)
		}
	}

	// validate metrics basic auth
	if o.MetricsBasicAuth != "" {
		str, err := base64.StdEncoding.DecodeString(o.MetricsBasicAuth)
		if err != nil {
			return fmt.Errorf("config: metrics_basic_auth must be a base64 encoded string")
		}

		if !strings.Contains(string(str), ":") {
			return fmt.Errorf("config: metrics_basic_auth should contain a user name and password separated by a colon")
		}
	}

	if o.MetricsCertificate != "" && o.MetricsCertificateKey != "" {
		_, err := cryptutil.CertificateFromBase64(o.MetricsCertificate, o.MetricsCertificateKey)
		if err != nil {
			return fmt.Errorf("config: invalid metrics_certificate or metrics_certificate_key: %w", err)
		}
	}

	if o.MetricsCertificateFile != "" && o.MetricsCertificateKeyFile != "" {
		_, err := cryptutil.CertificateFromFile(o.MetricsCertificateFile, o.MetricsCertificateKeyFile)
		if err != nil {
			return fmt.Errorf("config: invalid metrics_certificate_file or metrics_certificate_key_file: %w", err)
		}
	}

	// validate the Autocert options
	err = o.AutocertOptions.Validate()
	if err != nil {
		return err
	}

	return nil
}

// GetAuthenticateURL returns the AuthenticateURL in the options or 127.0.0.1.
func (o *Options) GetAuthenticateURL() (*url.URL, error) {
	rawurl := o.AuthenticateURLString
	if rawurl == "" {
		rawurl = "https://127.0.0.1"
	}
	return urlutil.ParseAndValidateURL(rawurl)
}

// GetInternalAuthenticateURL returns the internal AuthenticateURL in the options or the AuthenticateURL.
func (o *Options) GetInternalAuthenticateURL() (*url.URL, error) {
	rawurl := o.AuthenticateInternalURLString
	if rawurl == "" {
		return o.GetAuthenticateURL()
	}
	return urlutil.ParseAndValidateURL(o.AuthenticateInternalURLString)
}

// GetAuthorizeURLs returns the AuthorizeURLs in the options or 127.0.0.1:5443.
func (o *Options) GetAuthorizeURLs() ([]*url.URL, error) {
	if IsAll(o.Services) && o.AuthorizeURLString == "" && len(o.AuthorizeURLStrings) == 0 {
		u, err := urlutil.ParseAndValidateURL("http://127.0.0.1" + DefaultAlternativeAddr)
		if err != nil {
			return nil, err
		}
		return []*url.URL{u}, nil
	}
	return o.getURLs(append([]string{o.AuthorizeURLString}, o.AuthorizeURLStrings...)...)
}

// GetInternalAuthorizeURLs returns the internal AuthorizeURLs in the options or the AuthorizeURLs.
func (o *Options) GetInternalAuthorizeURLs() ([]*url.URL, error) {
	rawurl := o.AuthorizeInternalURLString
	if rawurl == "" {
		return o.GetAuthorizeURLs()
	}
	return o.getURLs(rawurl)
}

// GetDataBrokerURLs returns the DataBrokerURLs in the options or 127.0.0.1:5443.
func (o *Options) GetDataBrokerURLs() ([]*url.URL, error) {
	if IsAll(o.Services) && o.DataBrokerURLString == "" && len(o.DataBrokerURLStrings) == 0 {
		u, err := urlutil.ParseAndValidateURL("http://127.0.0.1" + DefaultAlternativeAddr)
		if err != nil {
			return nil, err
		}
		return []*url.URL{u}, nil
	}
	return o.getURLs(append([]string{o.DataBrokerURLString}, o.DataBrokerURLStrings...)...)
}

// GetInternalDataBrokerURLs returns the internal DataBrokerURLs in the options or the DataBrokerURLs.
func (o *Options) GetInternalDataBrokerURLs() ([]*url.URL, error) {
	rawurl := o.DataBrokerInternalURLString
	if rawurl == "" {
		return o.GetDataBrokerURLs()
	}
	return o.getURLs(rawurl)
}

func (o *Options) getURLs(strs ...string) ([]*url.URL, error) {
	var urls []*url.URL
	if o != nil {
		for _, str := range strs {
			if str == "" {
				continue
			}
			u, err := urlutil.ParseAndValidateURL(str)
			if err != nil {
				return nil, err
			}
			urls = append(urls, u)
		}
	}
	if len(urls) == 0 {
		u, _ := url.Parse("http://127.0.0.1" + DefaultAlternativeAddr)
		urls = append(urls, u)
	}
	return urls, nil
}

// GetForwardAuthURL returns the ForwardAuthURL.
func (o *Options) GetForwardAuthURL() (*url.URL, error) {
	rawurl := o.ForwardAuthURLString
	if rawurl == "" {
		return nil, nil
	}
	return urlutil.ParseAndValidateURL(rawurl)
}

// GetGRPCAddr gets the gRPC address.
func (o *Options) GetGRPCAddr() string {
	// to avoid port collision when running on localhost
	if IsAll(o.Services) && o.GRPCAddr == defaultOptions.GRPCAddr {
		return DefaultAlternativeAddr
	}
	return o.GRPCAddr
}

// GetGRPCInsecure gets whether or not gRPC is insecure.
func (o *Options) GetGRPCInsecure() bool {
	if IsAll(o.Services) {
		return true
	}
	return o.GRPCInsecure
}

// GetSignOutRedirectURL gets the SignOutRedirectURL.
func (o *Options) GetSignOutRedirectURL() (*url.URL, error) {
	rawurl := o.SignOutRedirectURLString
	if rawurl == "" {
		return nil, nil
	}
	return urlutil.ParseAndValidateURL(rawurl)
}

// GetMetricsCertificate returns the metrics certificate to use for TLS. `nil` will be
// returned if there is no certificate.
func (o *Options) GetMetricsCertificate() (*tls.Certificate, error) {
	if o.MetricsCertificate != "" && o.MetricsCertificateKey != "" {
		return cryptutil.CertificateFromBase64(o.MetricsCertificate, o.MetricsCertificateKey)
	}
	if o.MetricsCertificateFile != "" && o.MetricsCertificateKeyFile != "" {
		return cryptutil.CertificateFromFile(o.MetricsCertificateFile, o.MetricsCertificateKeyFile)
	}
	return nil, nil
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
	policies := make([]Policy, 0, len(o.Policies)+len(o.Routes)+len(o.AdditionalPolicies))
	policies = append(policies, o.Policies...)
	policies = append(policies, o.Routes...)
	policies = append(policies, o.AdditionalPolicies...)
	return policies
}

// GetMetricsBasicAuth gets the metrics basic auth username and password.
func (o *Options) GetMetricsBasicAuth() (username, password string, ok bool) {
	if o.MetricsBasicAuth == "" {
		return "", "", false
	}

	bs, err := base64.StdEncoding.DecodeString(o.MetricsBasicAuth)
	if err != nil {
		return "", "", false
	}

	idx := bytes.Index(bs, []byte{':'})
	if idx == -1 {
		return "", "", false
	}

	return string(bs[:idx]), string(bs[idx+1:]), true
}

// GetClientCA returns the client certificate authority. If neither client_ca nor client_ca_file is specified nil will
// be returned.
func (o *Options) GetClientCA() ([]byte, error) {
	if o.ClientCA != "" {
		return base64.StdEncoding.DecodeString(o.ClientCA)
	}
	if o.ClientCAFile != "" {
		return os.ReadFile(o.ClientCAFile)
	}
	return nil, nil
}

// GetDataBrokerCertificate gets the optional databroker certificate. This method will return nil if no certificate is
// specified.
func (o *Options) GetDataBrokerCertificate() (*tls.Certificate, error) {
	if o.DataBrokerStorageCertFile == "" || o.DataBrokerStorageCertKeyFile == "" {
		return nil, nil
	}
	return cryptutil.CertificateFromFile(o.DataBrokerStorageCertFile, o.DataBrokerStorageCertKeyFile)
}

// GetCertificates gets all the certificates from the options.
func (o *Options) GetCertificates() ([]tls.Certificate, error) {
	var certs []tls.Certificate
	if o.Cert != "" && o.Key != "" {
		cert, err := cryptutil.CertificateFromBase64(o.Cert, o.Key)
		if err != nil {
			return nil, fmt.Errorf("config: invalid base64 certificate: %w", err)
		}
		certs = append(certs, *cert)
	}
	for _, c := range o.CertificateFiles {
		cert, err := cryptutil.CertificateFromBase64(c.CertFile, c.KeyFile)
		if err != nil {
			cert, err = cryptutil.CertificateFromFile(c.CertFile, c.KeyFile)
		}
		if err != nil {
			return nil, fmt.Errorf("config: invalid certificate entry: %w", err)
		}
		certs = append(certs, *cert)
	}
	if o.CertFile != "" && o.KeyFile != "" {
		cert, err := cryptutil.CertificateFromFile(o.CertFile, o.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("config: bad cert file %w", err)
		}
		certs = append(certs, *cert)
	}
	return certs, nil
}

// GetSharedKey gets the decoded shared key.
func (o *Options) GetSharedKey() ([]byte, error) {
	sharedKey := o.SharedKey
	// mutual auth between services on the same host can be generated at runtime
	if IsAll(o.Services) && o.SharedKey == "" && o.DataBrokerStorageType == StorageInMemoryName {
		sharedKey = randomSharedKey
	}
	if sharedKey == "" {
		return nil, errors.New("empty shared secret")
	}
	if strings.TrimSpace(sharedKey) != sharedKey {
		return nil, errors.New("shared secret contains whitespace")
	}
	return base64.StdEncoding.DecodeString(sharedKey)
}

// GetGoogleCloudServerlessAuthenticationServiceAccount gets the GoogleCloudServerlessAuthenticationServiceAccount.
func (o *Options) GetGoogleCloudServerlessAuthenticationServiceAccount() string {
	if o.GoogleCloudServerlessAuthenticationServiceAccount == "" && o.Provider == "google" {
		return o.ServiceAccount
	}
	return o.GoogleCloudServerlessAuthenticationServiceAccount
}

// GetSetResponseHeaders gets the SetResponseHeaders.
func (o *Options) GetSetResponseHeaders() map[string]string {
	if _, ok := o.SetResponseHeaders[DisableHeaderKey]; ok {
		return map[string]string{}
	}
	return o.SetResponseHeaders
}

// GetQPS gets the QPS.
func (o *Options) GetQPS() float64 {
	if o.QPS < 1 {
		return 1
	}
	return o.QPS
}

// GetCodecType gets a codec type.
func (o *Options) GetCodecType() CodecType {
	if o.CodecType == CodecTypeUnset {
		if IsAll(o.Services) {
			return CodecTypeHTTP1
		}
		return CodecTypeAuto
	}
	return o.CodecType
}

// GetAllRouteableGRPCDomains returns all the possible gRPC domains handled by the Pomerium options.
func (o *Options) GetAllRouteableGRPCDomains() ([]string, error) {
	lookup := map[string]struct{}{}

	// authorize urls
	if IsAll(o.Services) {
		authorizeURLs, err := o.GetAuthorizeURLs()
		if err != nil {
			return nil, err
		}
		for _, u := range authorizeURLs {
			for _, h := range urlutil.GetDomainsForURL(*u) {
				lookup[h] = struct{}{}
			}
		}
	} else if IsAuthorize(o.Services) {
		authorizeURLs, err := o.GetInternalAuthorizeURLs()
		if err != nil {
			return nil, err
		}
		for _, u := range authorizeURLs {
			for _, h := range urlutil.GetDomainsForURL(*u) {
				lookup[h] = struct{}{}
			}
		}
	}

	// databroker urls
	if IsAll(o.Services) {
		dataBrokerURLs, err := o.GetDataBrokerURLs()
		if err != nil {
			return nil, err
		}
		for _, u := range dataBrokerURLs {
			for _, h := range urlutil.GetDomainsForURL(*u) {
				lookup[h] = struct{}{}
			}
		}
	} else if IsDataBroker(o.Services) {
		dataBrokerURLs, err := o.GetInternalDataBrokerURLs()
		if err != nil {
			return nil, err
		}
		for _, u := range dataBrokerURLs {
			for _, h := range urlutil.GetDomainsForURL(*u) {
				lookup[h] = struct{}{}
			}
		}
	}

	domains := make([]string, 0, len(lookup))
	for domain := range lookup {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	return domains, nil
}

// GetAllRouteableHTTPDomains returns all the possible HTTP domains handled by the Pomerium options.
func (o *Options) GetAllRouteableHTTPDomains() ([]string, error) {
	forwardAuthURL, err := o.GetForwardAuthURL()
	if err != nil {
		return nil, err
	}

	lookup := map[string]struct{}{}
	if IsAuthenticate(o.Services) {
		authenticateURL, err := o.GetInternalAuthenticateURL()
		if err != nil {
			return nil, err
		}
		for _, h := range urlutil.GetDomainsForURL(*authenticateURL) {
			lookup[h] = struct{}{}
		}
	}

	// policy urls
	if IsProxy(o.Services) {
		for _, policy := range o.GetAllPolicies() {
			for _, h := range urlutil.GetDomainsForURL(*policy.Source.URL) {
				lookup[h] = struct{}{}
			}
		}
		if forwardAuthURL != nil {
			for _, h := range urlutil.GetDomainsForURL(*forwardAuthURL) {
				lookup[h] = struct{}{}
			}
		}
	}

	domains := make([]string, 0, len(lookup))
	for domain := range lookup {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	return domains, nil
}

// Checksum returns the checksum of the current options struct
func (o *Options) Checksum() uint64 {
	return hashutil.MustHash(o)
}

func (o Options) indexCerts(ctx context.Context) certsIndex {
	idx := make(certsIndex)

	if o.CertFile != "" {
		cert, err := cryptutil.ParsePEMCertificateFromFile(o.CertFile)
		if err != nil {
			log.Error(ctx).Err(err).Str("file", o.CertFile).Msg("parsing local cert: skipped")
		} else {
			idx.addCert(cert)
		}
	} else if o.Cert != "" {
		if data, err := base64.StdEncoding.DecodeString(o.Cert); err != nil {
			log.Error(ctx).Err(err).Msg("bad base64 for local cert: skipped")
		} else if cert, err := cryptutil.ParsePEMCertificate(data); err != nil {
			log.Error(ctx).Err(err).Msg("parsing local cert: skipped")
		} else {
			idx.addCert(cert)
		}
	}

	for _, c := range o.CertificateFiles {
		cert, err := cryptutil.ParsePEMCertificateFromFile(c.CertFile)
		if err != nil {
			log.Error(ctx).Err(err).Str("file", c.CertFile).Msg("parsing local cert: skipped")
		} else {
			idx.addCert(cert)
		}
	}
	return idx
}

func (o *Options) applyExternalCerts(ctx context.Context, certs []*config.Settings_Certificate) {
	idx := o.indexCerts(ctx)
	for _, c := range certs {
		cert, err := cryptutil.ParsePEMCertificate(c.CertBytes)
		if err != nil {
			log.Error(ctx).Err(err).Msg("parsing cert from databroker: skipped")
			continue
		}
		if overlaps, name := idx.matchCert(cert); overlaps {
			log.Error(ctx).Err(err).Str("domain", name).Msg("overlaps with local certs: skipped")
			continue
		}
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
}

// ApplySettings modifies the config options using the given protobuf settings.
func (o *Options) ApplySettings(ctx context.Context, settings *config.Settings) {
	if settings == nil {
		return
	}

	if settings.InstallationId != nil {
		o.InstallationID = settings.GetInstallationId()
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
	o.applyExternalCerts(ctx, settings.GetCertificates())
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
	if settings.AuthenticateInternalServiceUrl != nil {
		o.AuthenticateInternalURLString = settings.GetAuthenticateInternalServiceUrl()
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
	if len(settings.AuthorizeServiceUrls) > 0 {
		o.AuthorizeURLStrings = settings.GetAuthorizeServiceUrls()
	}
	if settings.AuthorizeInternalServiceUrl != nil {
		o.AuthorizeInternalURLString = settings.GetAuthorizeInternalServiceUrl()
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
	if settings.SetResponseHeaders != nil && len(settings.SetResponseHeaders) > 0 {
		o.SetResponseHeaders = settings.SetResponseHeaders
	}
	if len(settings.JwtClaimsHeaders) > 0 {
		o.JWTClaimsHeaders = settings.GetJwtClaimsHeaders()
	}
	if settings.DefaultUpstreamTimeout != nil {
		o.DefaultUpstreamTimeout = settings.GetDefaultUpstreamTimeout().AsDuration()
	}
	if settings.MetricsAddress != nil {
		o.MetricsAddr = settings.GetMetricsAddress()
	}
	if settings.MetricsBasicAuth != nil {
		o.MetricsBasicAuth = settings.GetMetricsBasicAuth()
	}
	if len(settings.GetMetricsCertificate().GetCertBytes()) > 0 {
		o.MetricsCertificate = base64.StdEncoding.EncodeToString(settings.GetMetricsCertificate().GetCertBytes())
	}
	if len(settings.GetMetricsCertificate().GetKeyBytes()) > 0 {
		o.MetricsCertificateKey = base64.StdEncoding.EncodeToString(settings.GetMetricsCertificate().GetKeyBytes())
	}
	if settings.GetMetricsCertificate().GetCertFile() != "" {
		o.MetricsCertificateFile = settings.GetMetricsCertificate().GetCertFile()
	}
	if settings.GetMetricsCertificate().GetKeyFile() != "" {
		o.MetricsCertificateKeyFile = settings.GetMetricsCertificate().GetKeyFile()
	}
	if settings.GetMetricsClientCa() != "" {
		o.MetricsClientCA = settings.GetMetricsClientCa()
	}
	if settings.GetMetricsClientCaFile() != "" {
		o.MetricsClientCAFile = settings.GetMetricsClientCaFile()
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
	if settings.ForwardAuthUrl != nil {
		o.ForwardAuthURLString = settings.GetForwardAuthUrl()
	}
	if len(settings.DatabrokerServiceUrls) > 0 {
		o.DataBrokerURLStrings = settings.GetDatabrokerServiceUrls()
	}
	if settings.DatabrokerInternalServiceUrl != nil {
		o.DataBrokerInternalURLString = settings.GetDatabrokerInternalServiceUrl()
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
	if settings.AutocertCa != nil {
		o.AutocertOptions.CA = settings.GetAutocertCa()
	}
	if settings.AutocertEmail != nil {
		o.AutocertOptions.Email = settings.GetAutocertEmail()
	}
	if settings.AutocertEabKeyId != nil {
		o.AutocertOptions.EABKeyID = settings.GetAutocertEabKeyId()
	}
	if settings.AutocertEabMacKey != nil {
		o.AutocertOptions.EABMACKey = settings.GetAutocertEabMacKey()
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
	if settings.AutocertTrustedCa != nil {
		o.AutocertOptions.TrustedCA = settings.GetAutocertTrustedCa()
	}
	if settings.AutocertTrustedCaFile != nil {
		o.AutocertOptions.TrustedCAFile = settings.GetAutocertTrustedCaFile()
	}
	if settings.SkipXffAppend != nil {
		o.SkipXffAppend = settings.GetSkipXffAppend()
	}
	if settings.XffNumTrustedHops != nil {
		o.XffNumTrustedHops = settings.GetXffNumTrustedHops()
	}
	if len(settings.ProgrammaticRedirectDomainWhitelist) > 0 {
		o.ProgrammaticRedirectDomainWhitelist = settings.GetProgrammaticRedirectDomainWhitelist()
	}
	if settings.AuditKey != nil {
		o.AuditKey = &PublicKeyEncryptionKeyOptions{
			ID:   settings.AuditKey.GetId(),
			Data: base64.StdEncoding.EncodeToString(settings.AuditKey.GetData()),
		}
	}
	if settings.CodecType != nil {
		o.CodecType = CodecTypeFromEnvoy(settings.GetCodecType())
	}
	if settings.ClientCrl != nil {
		o.ClientCRL = settings.GetClientCrl()
	}
	if settings.ClientCrlFile != nil {
		o.ClientCRLFile = settings.GetClientCrlFile()
	}
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
