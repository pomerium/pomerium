package config

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"iter"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"

	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/go-viper/mapstructure/v2"
	goset "github.com/hashicorp/go-set/v3"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
	"github.com/volatiletech/null/v9"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/csrf"
	"github.com/pomerium/pomerium/config/otelconfig"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/fileutil"
	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/hpke"
	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oauth/apple"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

// DisableHeaderKey is the key used to check whether to disable setting header
const DisableHeaderKey = "disable"

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

	// Debug is deprecated.
	Debug bool `mapstructure:"pomerium_debug" yaml:"pomerium_debug,omitempty"`

	// LogLevel sets the global override for log level. All Loggers will use at least this value.
	// Possible options are "info","warn","debug" and "error". Defaults to "info".
	LogLevel LogLevel `mapstructure:"log_level" yaml:"log_level,omitempty"`

	// ProxyLogLevel sets the log level for the proxy service.
	// Possible options are "info","warn", and "error". Defaults to the value of `LogLevel`.
	ProxyLogLevel LogLevel `mapstructure:"proxy_log_level" yaml:"proxy_log_level,omitempty"`

	// AccessLogFields are the fields to log in access logs.
	AccessLogFields []log.AccessLogField `mapstructure:"access_log_fields" yaml:"access_log_fields,omitempty"`

	// AuthorizeLogFields are the fields to log in authorize logs.
	AuthorizeLogFields []log.AuthorizeLogField `mapstructure:"authorize_log_fields" yaml:"authorize_log_fields,omitempty"`

	// SharedKey is the shared secret authorization key used to mutually authenticate
	// requests between services.
	SharedKey        string `mapstructure:"shared_secret" yaml:"shared_secret,omitempty"`
	SharedSecretFile string `mapstructure:"shared_secret_file" yaml:"shared_secret_file,omitempty"`

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
	// If this setting is not specified, the value defaults to V4_PREFERRED.
	DNSLookupFamily string `mapstructure:"dns_lookup_family" yaml:"dns_lookup_family,omitempty"`

	CertificateData  []*config.Settings_Certificate
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
	CookieName       string        `mapstructure:"cookie_name" yaml:"cookie_name,omitempty"`
	CookieSecret     string        `mapstructure:"cookie_secret" yaml:"cookie_secret,omitempty"`
	CookieSecretFile string        `mapstructure:"cookie_secret_file" yaml:"cookie_secret_file,omitempty"`
	CookieDomain     string        `mapstructure:"cookie_domain" yaml:"cookie_domain,omitempty"`
	CookieHTTPOnly   bool          `mapstructure:"cookie_http_only" yaml:"cookie_http_only,omitempty"`
	CookieExpire     time.Duration `mapstructure:"cookie_expire" yaml:"cookie_expire,omitempty"`
	CookieSameSite   string        `mapstructure:"cookie_same_site" yaml:"cookie_same_site,omitempty"`

	// Identity provider configuration variables as specified by RFC6749
	// https://openid.net/specs/openid-connect-basic-1_0.html#RFC6749
	ClientID                       string    `mapstructure:"idp_client_id" yaml:"idp_client_id,omitempty"`
	ClientSecret                   string    `mapstructure:"idp_client_secret" yaml:"idp_client_secret,omitempty"`
	ClientSecretFile               string    `mapstructure:"idp_client_secret_file" yaml:"idp_client_secret_file,omitempty"`
	Provider                       string    `mapstructure:"idp_provider" yaml:"idp_provider,omitempty"`
	ProviderURL                    string    `mapstructure:"idp_provider_url" yaml:"idp_provider_url,omitempty"`
	Scopes                         []string  `mapstructure:"idp_scopes" yaml:"idp_scopes,omitempty"`
	IDPAccessTokenAllowedAudiences *[]string `mapstructure:"idp_access_token_allowed_audiences" yaml:"idp_access_token_allowed_audiences,omitempty"`

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

	// DeriveInternalDomainCert is an option that would derive certificate authority
	// and domain certificates from the shared key and use them for internal communication
	DeriveInternalDomainCert *string `mapstructure:"tls_derive" yaml:"tls_derive,omitempty"`

	// SigningKey is the private key used to add a JWT-signature to upstream requests.
	// https://www.pomerium.com/docs/topics/getting-users-identity.html
	SigningKey     string `mapstructure:"signing_key" yaml:"signing_key,omitempty"`
	SigningKeyFile string `mapstructure:"signing_key_file" yaml:"signing_key_file,omitempty"`

	HeadersEnv string `yaml:",omitempty"`
	// SetResponseHeaders to set on all proxied requests. Add a 'disable' key map to turn off.
	SetResponseHeaders map[string]string `yaml:",omitempty"`

	// List of JWT claims to insert as x-pomerium-claim-* headers on proxied requests
	JWTClaimsHeaders JWTClaimHeaders `mapstructure:"jwt_claims_headers" yaml:"jwt_claims_headers,omitempty"`

	// JWTIssuerFormat controls the default format of the 'iss' claim in JWTs passed to upstream services.
	// Possible values:
	// - "hostOnly" (default): Issuer strings will be the hostname of the route, with no scheme or trailing slash.
	// - "uri": Issuer strings will be a complete URI, including the scheme and ending with a trailing slash.
	JWTIssuerFormat JWTIssuerFormat `mapstructure:"jwt_issuer_format" yaml:"jwt_issuer_format,omitempty"`

	// BearerTokenFormat indicates how authorization bearer tokens are interepreted. Possible values:
	// - "default": Only Bearer tokens prefixed with Pomerium- will be interpreted by Pomerium.
	// - "idp_access_token": The Bearer token will be interpreted as an IdP access token.
	// - "idp_identity_token": The Bearer token will be interpreted as an IdP identity token.
	// When unset "default" will be used.
	BearerTokenFormat *BearerTokenFormat `mapstructure:"bearer_token_format" yaml:"bearer_token_format,omitempty"`

	// Allowlist of group names/IDs to include in the Pomerium JWT.
	JWTGroupsFilter JWTGroupsFilter

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

	Tracing otelconfig.Config `mapstructure:",squash" yaml:",inline"`

	// GRPC Service Settings

	// GRPCAddr specifies the host and port on which the server should serve
	// gRPC requests. If running in all-in-one mode, ":5443" (localhost:5443) is used.
	GRPCAddr string `mapstructure:"grpc_address" yaml:"grpc_address,omitempty"`

	// GRPCInsecure disables transport security.
	// If running in all-in-one mode, defaults to true.
	GRPCInsecure *bool `mapstructure:"grpc_insecure" yaml:"grpc_insecure,omitempty"`

	GRPCClientTimeout time.Duration `mapstructure:"grpc_client_timeout" yaml:"grpc_client_timeout,omitempty"`

	// SSH Settings

	SSHAddr          string    `mapstructure:"ssh_address" yaml:"ssh_address,omitempty"`
	SSHHostKeyFiles  *[]string `mapstructure:"ssh_host_key_files" yaml:"ssh_host_key_files,omitempty"`
	SSHHostKeys      *[]string `mapstructure:"ssh_host_keys" yaml:"ssh_host_keys,omitempty"`
	SSHUserCAKeyFile string    `mapstructure:"ssh_user_ca_key_file" yaml:"ssh_user_ca_key_file,omitempty"`
	SSHUserCAKey     string    `mapstructure:"ssh_user_ca_key" yaml:"ssh_user_ca_key,omitempty"`

	// DataBrokerURLString is the routable destination of the databroker service's gRPC endpoint.
	DataBrokerURLString         string   `mapstructure:"databroker_service_url" yaml:"databroker_service_url,omitempty"`
	DataBrokerURLStrings        []string `mapstructure:"databroker_service_urls" yaml:"databroker_service_urls,omitempty"`
	DataBrokerInternalURLString string   `mapstructure:"databroker_internal_service_url" yaml:"databroker_internal_service_url,omitempty"`
	// DataBrokerStorageType is the storage backend type that databroker will use.
	// Supported type: memory, postgres
	DataBrokerStorageType string `mapstructure:"databroker_storage_type" yaml:"databroker_storage_type,omitempty"`
	// DataBrokerStorageConnectionString is the data source name for storage backend.
	DataBrokerStorageConnectionString     string `mapstructure:"databroker_storage_connection_string" yaml:"databroker_storage_connection_string,omitempty"`
	DataBrokerStorageConnectionStringFile string `mapstructure:"databroker_storage_connection_string_file" yaml:"databroker_storage_connection_string_file,omitempty"`

	// DownstreamMTLS holds all downstream mTLS settings.
	DownstreamMTLS DownstreamMTLSSettings `mapstructure:"downstream_mtls" yaml:"downstream_mtls,omitempty"`

	// GoogleCloudServerlessAuthenticationServiceAccount is the service account to use for GCP serverless authentication.
	// If unset, the GCP metadata server will be used to query for identity tokens.
	GoogleCloudServerlessAuthenticationServiceAccount string `mapstructure:"google_cloud_serverless_authentication_service_account" yaml:"google_cloud_serverless_authentication_service_account,omitempty"`

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
	ProgrammaticRedirectDomainWhitelist []string `mapstructure:"programmatic_redirect_domain_whitelist" yaml:"programmatic_redirect_domain_whitelist,omitempty" json:"programmatic_redirect_domain_whitelist,omitempty"`

	// CodecType is the codec to use for downstream connections.
	CodecType CodecType `mapstructure:"codec_type" yaml:"codec_type"`

	BrandingOptions httputil.BrandingOptions

	PassIdentityHeaders *bool `mapstructure:"pass_identity_headers" yaml:"pass_identity_headers"`

	RuntimeFlags RuntimeFlags `mapstructure:"runtime_flags" yaml:"runtime_flags,omitempty"`

	HTTP3AdvertisePort       null.Uint32               `mapstructure:"-" yaml:"-" json:"-"`
	CircuitBreakerThresholds *CircuitBreakerThresholds `mapstructure:"circuit_breaker_thresholds" yaml:"circuit_breaker_thresholds" json:"circuit_breaker_thresholds"`
}

type certificateFilePair struct {
	// CertFile and KeyFile is the x509 certificate used to hydrate TLSCertificate
	CertFile string `mapstructure:"cert" yaml:"cert,omitempty"`
	KeyFile  string `mapstructure:"key" yaml:"key,omitempty"`
}

// DefaultOptions are the default configuration options for pomerium
var defaultOptions = Options{
	LogLevel:                 LogLevelInfo,
	Services:                 "all",
	CookieHTTPOnly:           true,
	CookieExpire:             14 * time.Hour,
	CookieName:               "_pomerium",
	DefaultUpstreamTimeout:   30 * time.Second,
	Addr:                     ":443",
	ReadTimeout:              30 * time.Second,
	WriteTimeout:             0, // support streaming by default
	IdleTimeout:              5 * time.Minute,
	GRPCAddr:                 ":443",
	GRPCClientTimeout:        10 * time.Second, // Try to withstand transient service failures for a single request
	AuthenticateCallbackPath: "/oauth2/callback",

	AutocertOptions: AutocertOptions{
		Folder: fileutil.DataDir(),
	},
	DataBrokerStorageType:               "memory",
	SkipXffAppend:                       false,
	XffNumTrustedHops:                   0,
	EnvoyAdminAccessLogPath:             os.DevNull,
	EnvoyAdminProfilePath:               os.DevNull,
	ProgrammaticRedirectDomainWhitelist: []string{"localhost"},
}

// IsRuntimeFlagSet returns true if the runtime flag is sets
func (o *Options) IsRuntimeFlagSet(flag RuntimeFlag) bool {
	return o.RuntimeFlags[flag]
}

var defaultSetResponseHeaders = map[string]string{
	"X-Frame-Options":           "SAMEORIGIN",
	"X-XSS-Protection":          "1; mode=block",
	"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
}

// NewDefaultOptions returns a copy the default options. It's the caller's
// responsibility to do a follow up Validate call.
func NewDefaultOptions() *Options {
	newOpts := defaultOptions
	newOpts.RuntimeFlags = DefaultRuntimeFlags()
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
		return int64(o.NumPolicies())
	})

	return o, nil
}

func optionsFromViper(configFile string) (*Options, error) {
	// start a copy of the default options
	o := NewDefaultOptions()
	v := o.viper
	// Load up config
	err := bindEnvs(v)
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
	if err := checkConfigKeysErrors(configFile, o, metadata.Unused); err != nil {
		return nil, err
	}

	// This is necessary because v.Unmarshal will overwrite .viper field.
	o.viper = v

	if err := o.Validate(); err != nil {
		return nil, fmt.Errorf("validation error %w", err)
	}
	return o, nil
}

func checkConfigKeysErrors(configFile string, o *Options, unused []string) error {
	checks := CheckUnknownConfigFields(unused)
	ctx := context.Background()
	errInvalidConfigKeys := errors.New("some configuration options are no longer supported, please check logs for details")
	var err error

	for _, check := range checks {
		var evt *zerolog.Event
		switch check.KeyAction {
		case KeyActionError:
			evt = log.Ctx(ctx).Error()
			err = errInvalidConfigKeys
		default:
			evt = log.Ctx(ctx).Error()
		}
		evt.Str("config-file", configFile).Str("key", check.Key)
		if check.DocsURL != "" {
			evt = evt.Str("help", check.DocsURL)
		}
		evt.Msg(string(check.FieldCheckMsg))
	}

	// check for unknown runtime flags
	for flag := range o.RuntimeFlags {
		if _, ok := defaultRuntimeFlags[flag]; !ok {
			log.Ctx(ctx).Error().Str("config-file", configFile).Str("flag", string(flag)).Msg("unknown runtime flag")
		}
	}

	return err
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
		p := o.AdditionalPolicies[i]
		if err := p.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (o *Options) viperSet(key string, value any) {
	o.viper.Set(key, value)
}

func (o *Options) viperIsSet(key string) bool {
	return o.viper.IsSet(key)
}

// parseHeaders handles unmarshalling any custom headers correctly from the
// environment or viper's parsed keys
func (o *Options) parseHeaders(_ context.Context) error {
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

// bindEnvs adds a Viper environment variable binding for each field in the
// Options struct (including nested structs), based on the mapstructure tag.
func bindEnvs(v *viper.Viper) error {
	if _, err := bindEnvsRecursive(reflect.TypeOf(Options{}), v, "", ""); err != nil {
		return err
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

	return nil
}

// bindEnvsRecursive binds all fields of the provided struct type that have a
// "mapstructure" tag to corresponding environment variables, recursively. If a
// nested struct contains no fields with a "mapstructure" tag, a binding will
// be added for the struct itself (e.g. null.Bool).
func bindEnvsRecursive(t reflect.Type, v *viper.Viper, keyPrefix, envPrefix string) (bool, error) {
	anyFieldHasMapstructureTag := false
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag, hasTag := field.Tag.Lookup("mapstructure")
		if !hasTag || tag == "-" {
			continue
		}

		anyFieldHasMapstructureTag = true

		key, _, _ := strings.Cut(tag, ",")
		keyPath := keyPrefix + key
		envName := envPrefix + strings.ToUpper(key)

		if field.Type.Kind() == reflect.Struct {
			newKeyPrefix := keyPath
			newEnvPrefix := envName
			if key != "" {
				newKeyPrefix += "."
				newEnvPrefix += "_"
			}
			nestedMapstructure, err := bindEnvsRecursive(field.Type, v, newKeyPrefix, newEnvPrefix)
			if err != nil {
				return false, err
			} else if nestedMapstructure {
				// If we've bound any nested fields from this struct, do not
				// also bind this struct itself.
				continue
			}
		}

		if key != "" {
			if err := v.BindEnv(keyPath, envName); err != nil {
				return false, fmt.Errorf("failed to bind field '%s' to env var '%s': %w",
					field.Name, envName, err)
			}
		}
	}
	return anyFieldHasMapstructureTag, nil
}

// Validate ensures the Options fields are valid, and hydrated.
func (o *Options) Validate() error {
	ctx := context.TODO()
	if !IsValidService(o.Services) {
		return fmt.Errorf("config: %s is an invalid service type", o.Services)
	}

	switch o.DataBrokerStorageType {
	case StorageInMemoryName:
	case StoragePostgresName:
		if o.DataBrokerStorageConnectionString == "" && o.DataBrokerStorageConnectionStringFile == "" {
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

	if o.PolicyFile != "" {
		return errors.New("config: policy file setting is deprecated")
	}
	if err := o.parsePolicy(); err != nil {
		return fmt.Errorf("config: failed to parse policy: %w", err)
	}

	if err := o.parseHeaders(ctx); err != nil {
		return fmt.Errorf("config: failed to parse headers: %w", err)
	}

	if o.Cert != "" || o.Key != "" {
		_, err := cryptutil.CertificateFromBase64(o.Cert, o.Key)
		if err != nil {
			return fmt.Errorf("config: bad cert base64 %w", err)
		}
	}

	for _, c := range o.CertificateData {
		_, err := tls.X509KeyPair(c.GetCertBytes(), c.GetKeyBytes())
		if err != nil {
			return fmt.Errorf("config: bad cert entry, cert is invalid: %w", err)
		}
	}

	for _, c := range o.CertificateFiles {
		_, err := cryptutil.CertificateFromFile(c.CertFile, c.KeyFile)
		if err != nil {
			return fmt.Errorf("config: bad cert entry, file reference invalid. %w", err)
		}
	}

	if o.CertFile != "" || o.KeyFile != "" {
		_, err := cryptutil.CertificateFromFile(o.CertFile, o.KeyFile)
		if err != nil {
			return fmt.Errorf("config: bad cert file %w", err)
		}
	}

	if err := o.DownstreamMTLS.validate(); err != nil {
		return fmt.Errorf("config: bad downstream mTLS settings: %w", err)
	}

	// strip quotes from redirect address (#811)
	o.HTTPRedirectAddr = strings.Trim(o.HTTPRedirectAddr, `"'`)

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

	if err := ValidateCookieSameSite(o.CookieSameSite); err != nil {
		return fmt.Errorf("config: invalid cookie_same_site: %w", err)
	}

	if err := ValidateLogLevel(o.LogLevel); err != nil {
		return fmt.Errorf("config: invalid log_level: %w", err)
	}

	if err := ValidateLogLevel(o.ProxyLogLevel); err != nil {
		return fmt.Errorf("config: invalid proxy_log_level: %w", err)
	}

	for _, field := range o.AccessLogFields {
		if err := field.Validate(); err != nil {
			return fmt.Errorf("config: invalid access_log_fields: %w", err)
		}
	}

	for _, field := range o.AuthorizeLogFields {
		if err := field.Validate(); err != nil {
			return fmt.Errorf("config: invalid authorize_log_fields: %w", err)
		}
	}

	if !o.JWTIssuerFormat.Valid() {
		return fmt.Errorf("config: unsupported jwt_issuer_format value %q", o.JWTIssuerFormat)
	}

	if o.SSHAddr != "" {
		check := func(optionName, keyFile string) error {
			if info, err := os.Stat(keyFile); err != nil {
				return fmt.Errorf("config: invalid ssh %s key file %s: %w", optionName, keyFile, err)
			} else if (info.Mode() & 0o77) != 0 {
				return fmt.Errorf("config: invalid ssh %s key file %s: permissions are too open", optionName, keyFile)
			}
			return nil
		}
		if o.SSHHostKeyFiles != nil {
			for _, keyFile := range *o.SSHHostKeyFiles {
				if err := check("host", keyFile); err != nil {
					return err
				}
			}
		}
		if o.SSHUserCAKeyFile != "" {
			if err := check("user ca", o.SSHUserCAKeyFile); err != nil {
				return err
			}
		}
	}

	return nil
}

// GetDeriveInternalDomain returns an optional internal domain name to use for gRPC endpoint
func (o *Options) GetDeriveInternalDomain() string {
	if o.DeriveInternalDomainCert == nil {
		return ""
	}
	return strings.ToLower(*o.DeriveInternalDomainCert)
}

// GetAuthenticateURL returns the AuthenticateURL in the options or 127.0.0.1.
func (o *Options) GetAuthenticateURL() (*url.URL, error) {
	rawURL := o.AuthenticateURLString
	if rawURL == "" {
		rawURL = "https://authenticate.pomerium.app"
	}
	return urlutil.ParseAndValidateURL(rawURL)
}

// GetInternalAuthenticateURL returns the internal AuthenticateURL in the options or the AuthenticateURL.
func (o *Options) GetInternalAuthenticateURL() (*url.URL, error) {
	rawURL := o.AuthenticateInternalURLString
	if rawURL == "" {
		return o.GetAuthenticateURL()
	}
	return urlutil.ParseAndValidateURL(o.AuthenticateInternalURLString)
}

// UseStatelessAuthenticateFlow returns true if the stateless authentication
// flow should be used (i.e. for hosted authenticate).
func (o *Options) UseStatelessAuthenticateFlow() bool {
	if flow := os.Getenv("DEBUG_FORCE_AUTHENTICATE_FLOW"); flow != "" {
		if flow == "stateless" {
			return true
		} else if flow == "stateful" {
			return false
		}
		log.Error().
			Msgf("ignoring unknown DEBUG_FORCE_AUTHENTICATE_FLOW setting %q", flow)
	}
	u, err := o.GetInternalAuthenticateURL()
	if err != nil {
		return false
	}
	return urlutil.IsHostedAuthenticateDomain(u.Hostname())
}

// SupportsUserRefresh returns true if the config options support refreshing of user sessions.
func (o *Options) SupportsUserRefresh() bool {
	if o == nil {
		return false
	}

	if o.Provider == "" {
		return false
	}

	u, err := o.GetInternalAuthenticateURL()
	if err != nil {
		return false
	}

	return !urlutil.IsHostedAuthenticateDomain(u.Hostname())
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
	if o.GRPCInsecure != nil {
		return *o.GRPCInsecure
	}
	if IsAll(o.Services) {
		return true
	}
	return false
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
	clientSecret, err := o.GetClientSecret()
	if err != nil {
		return oauth.Options{}, err
	}
	return oauth.Options{
		RedirectURL:  redirectURL,
		ProviderName: o.Provider,
		ProviderURL:  o.ProviderURL,
		ClientID:     o.ClientID,
		ClientSecret: clientSecret,
		Scopes:       o.Scopes,
	}, nil
}

// GetAllPolicies gets all the policies in the options.
func (o *Options) GetAllPolicies() iter.Seq[*Policy] {
	return func(yield func(*Policy) bool) {
		if o == nil {
			return
		}
		for i := range len(o.Policies) {
			if !yield(&o.Policies[i]) {
				return
			}
		}
		for i := range len(o.Routes) {
			if !yield(&o.Routes[i]) {
				return
			}
		}
		for i := range len(o.AdditionalPolicies) {
			if !yield(&o.AdditionalPolicies[i]) {
				return
			}
		}
	}
}

// GetAllPolicies gets all the policies in the options.
func (o *Options) GetAllPoliciesIndexed() iter.Seq2[int, *Policy] {
	return func(yield func(int, *Policy) bool) {
		if o == nil {
			return
		}
		index := 0
		nextIndex := func() int {
			i := index
			index++
			return i
		}
		for i := range len(o.Policies) {
			if !yield(nextIndex(), &o.Policies[i]) {
				return
			}
		}
		for i := range len(o.Routes) {
			if !yield(nextIndex(), &o.Routes[i]) {
				return
			}
		}
		for i := range len(o.AdditionalPolicies) {
			if !yield(nextIndex(), &o.AdditionalPolicies[i]) {
				return
			}
		}
	}
}

func (o *Options) NumPolicies() int {
	return len(o.Policies) + len(o.Routes) + len(o.AdditionalPolicies)
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

// HasAnyDownstreamMTLSClientCA returns true if there is a global downstream
// client CA or there are any per-route downstream client CAs.
func (o *Options) HasAnyDownstreamMTLSClientCA() bool {
	// All the CA settings should already have been validated.
	ca, _ := o.DownstreamMTLS.GetCA()
	if len(ca) > 0 {
		return true
	}
	for p := range o.GetAllPolicies() {
		// We don't need to check TLSDownstreamClientCAFile here because
		// Policy.Validate() will populate TLSDownstreamClientCA when
		// TLSDownstreamClientCAFile is set.
		if p.TLSDownstreamClientCA != "" {
			return true
		}
	}
	return false
}

// GetDataBrokerStorageConnectionString gets the databroker storage connection string from either a file
// or the config option directly. If from a file spaces are trimmed off the ends.
func (o *Options) GetDataBrokerStorageConnectionString() (string, error) {
	if o.DataBrokerStorageConnectionStringFile != "" {
		bs, err := os.ReadFile(o.DataBrokerStorageConnectionStringFile)
		return strings.TrimSpace(string(bs)), err
	}

	return o.DataBrokerStorageConnectionString, nil
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
		cert, err := cryptutil.CertificateFromFile(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("config: invalid certificate entry: %w", err)
		}
		certs = append(certs, *cert)
	}
	for _, c := range o.CertificateData {
		cert, err := tls.X509KeyPair(c.GetCertBytes(), c.GetKeyBytes())
		if err != nil {
			return nil, fmt.Errorf("config: invalid certificate entry: %w", err)
		}
		certs = append(certs, cert)
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

// HasCertificates returns true if options has any certificates.
func (o *Options) HasCertificates() bool {
	return o.Cert != "" ||
		o.Key != "" ||
		len(o.CertificateFiles) > 0 ||
		o.CertFile != "" ||
		o.KeyFile != "" ||
		len(o.CertificateData) > 0
}

// GetX509Certificates gets all the x509 certificates from the options. Invalid certificates are ignored.
func (o *Options) GetX509Certificates() []*x509.Certificate {
	var certs []*x509.Certificate

	if o.CertFile != "" {
		cert, err := cryptutil.ParsePEMCertificateFromFile(o.CertFile)
		if err != nil {
			log.Error().Err(err).Str("file", o.CertFile).Msg("invalid cert_file")
		} else {
			certs = append(certs, cert)
		}
	} else if o.Cert != "" {
		if cert, err := cryptutil.ParsePEMCertificateFromBase64(o.Cert); err != nil {
			log.Error().Err(err).Msg("invalid cert")
		} else {
			certs = append(certs, cert)
		}
	}

	for _, c := range o.CertificateData {
		cert, err := cryptutil.ParsePEMCertificate(c.GetCertBytes())
		if err != nil {
			log.Error().Err(err).Msg("invalid certificate")
		} else {
			certs = append(certs, cert)
		}
	}

	for _, c := range o.CertificateFiles {
		cert, err := cryptutil.ParsePEMCertificateFromFile(c.CertFile)
		if err != nil {
			log.Error().Err(err).Msg("invalid certificate_file")
		} else {
			certs = append(certs, cert)
		}
	}

	return certs
}

// GetSharedKey gets the decoded shared key.
func (o *Options) GetSharedKey() ([]byte, error) {
	sharedKey := o.SharedKey
	if o.SharedSecretFile != "" {
		bs, err := os.ReadFile(o.SharedSecretFile)
		if err != nil {
			return nil, err
		}
		sharedKey = string(bs)
	}
	// mutual auth between services on the same host can be generated at runtime
	if IsAll(o.Services) && sharedKey == "" {
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

// GetHPKEPrivateKey gets the hpke.PrivateKey dervived from the shared key.
func (o *Options) GetHPKEPrivateKey() (*hpke.PrivateKey, error) {
	sharedKey, err := o.GetSharedKey()
	if err != nil {
		return nil, err
	}

	return hpke.DerivePrivateKey(sharedKey), nil
}

// GetGoogleCloudServerlessAuthenticationServiceAccount gets the GoogleCloudServerlessAuthenticationServiceAccount.
func (o *Options) GetGoogleCloudServerlessAuthenticationServiceAccount() string {
	return o.GoogleCloudServerlessAuthenticationServiceAccount
}

// GetSetResponseHeaders gets the SetResponseHeaders.
func (o *Options) GetSetResponseHeaders() map[string]string {
	return o.GetSetResponseHeadersForPolicy(nil)
}

// GetSetResponseHeadersForPolicy gets the SetResponseHeaders for a policy.
func (o *Options) GetSetResponseHeadersForPolicy(policy *Policy) map[string]string {
	hdrs := make(map[string]string)
	for k, v := range o.SetResponseHeaders {
		hdrs[k] = v
	}

	if o.SetResponseHeaders == nil {
		for k, v := range defaultSetResponseHeaders {
			hdrs[k] = v
		}

		if !o.HasCertificates() || o.AutocertOptions.UseStaging {
			delete(hdrs, "Strict-Transport-Security")
		}
	}
	if _, ok := hdrs[DisableHeaderKey]; ok {
		hdrs = make(map[string]string)
	}

	if policy != nil && policy.SetResponseHeaders != nil {
		for k, v := range policy.SetResponseHeaders {
			hdrs[k] = v
		}
	}
	if _, ok := hdrs[DisableHeaderKey]; ok {
		hdrs = make(map[string]string)
	}

	return hdrs
}

// GetCodecType gets a codec type.
func (o *Options) GetCodecType() CodecType {
	if o.CodecType == CodecTypeUnset {
		return CodecTypeAuto
	}
	return o.CodecType
}

// GetAllRouteableGRPCHosts returns all the possible gRPC hosts handled by the Pomerium options.
func (o *Options) GetAllRouteableGRPCHosts() ([]string, error) {
	hosts := goset.NewTreeSet(cmp.Compare[string])

	// authorize urls
	if IsAll(o.Services) {
		authorizeURLs, err := o.GetAuthorizeURLs()
		if err != nil {
			return nil, err
		}
		for _, u := range authorizeURLs {
			hosts.InsertSlice(urlutil.GetDomainsForURL(u, true))
		}
	} else if IsAuthorize(o.Services) {
		authorizeURLs, err := o.GetInternalAuthorizeURLs()
		if err != nil {
			return nil, err
		}
		for _, u := range authorizeURLs {
			hosts.InsertSlice(urlutil.GetDomainsForURL(u, true))
		}
	}

	// databroker urls
	if IsAll(o.Services) {
		dataBrokerURLs, err := o.GetDataBrokerURLs()
		if err != nil {
			return nil, err
		}
		for _, u := range dataBrokerURLs {
			hosts.InsertSlice(urlutil.GetDomainsForURL(u, true))
		}
	} else if IsDataBroker(o.Services) {
		dataBrokerURLs, err := o.GetInternalDataBrokerURLs()
		if err != nil {
			return nil, err
		}
		for _, u := range dataBrokerURLs {
			hosts.InsertSlice(urlutil.GetDomainsForURL(u, true))
		}
	}

	return hosts.Slice(), nil
}

// GetAllRouteableHTTPHosts returns all the possible HTTP hosts handled by the Pomerium options.
func (o *Options) GetAllRouteableHTTPHosts() ([]string, map[string]bool, error) {
	hosts := goset.NewTreeSet(cmp.Compare[string])
	mcpHosts := make(map[string]bool)

	if IsAuthenticate(o.Services) {
		if o.AuthenticateInternalURLString != "" {
			authenticateURL, err := o.GetInternalAuthenticateURL()
			if err != nil {
				return nil, nil, err
			}
			domains := urlutil.GetDomainsForURL(authenticateURL, !o.IsRuntimeFlagSet(RuntimeFlagMatchAnyIncomingPort))
			hosts.InsertSlice(domains)
		}

		if o.AuthenticateURLString != "" {
			authenticateURL, err := o.GetAuthenticateURL()
			if err != nil {
				return nil, nil, err
			}
			domains := urlutil.GetDomainsForURL(authenticateURL, !o.IsRuntimeFlagSet(RuntimeFlagMatchAnyIncomingPort))
			hosts.InsertSlice(domains)
		}
	}

	// policy urls
	if IsProxy(o.Services) {
		for policy := range o.GetAllPolicies() {
			fromURL, err := urlutil.ParseAndValidateURL(policy.From)
			if err != nil {
				return nil, nil, err
			}

			domains := urlutil.GetDomainsForURL(fromURL, !o.IsRuntimeFlagSet(RuntimeFlagMatchAnyIncomingPort))
			hosts.InsertSlice(domains)

			// Track if the domains are associated with an MCP policy
			if policy.IsMCPServer() {
				for _, domain := range domains {
					mcpHosts[domain] = true
				}
			}

			if policy.TLSDownstreamServerName != "" {
				tlsURL := fromURL.ResolveReference(&url.URL{Host: policy.TLSDownstreamServerName})
				tlsDomains := urlutil.GetDomainsForURL(tlsURL, !o.IsRuntimeFlagSet(RuntimeFlagMatchAnyIncomingPort))
				hosts.InsertSlice(tlsDomains)

				// Track if the TLS domains are associated with an MCP policy
				if policy.IsMCPServer() {
					for _, domain := range tlsDomains {
						mcpHosts[domain] = true
					}
				}
			}
		}
	}

	return hosts.Slice(), mcpHosts, nil
}

// GetClientSecret gets the client secret.
func (o *Options) GetClientSecret() (string, error) {
	if o == nil {
		return "", nil
	}
	if o.ClientSecretFile != "" {
		bs, err := os.ReadFile(o.ClientSecretFile)
		if err != nil {
			return "", err
		}
		return string(bs), nil
	}
	return o.ClientSecret, nil
}

// GetCookieSecret gets the decoded cookie secret.
func (o *Options) GetCookieSecret() ([]byte, error) {
	cookieSecret := o.CookieSecret
	if o.CookieSecretFile != "" {
		bs, err := os.ReadFile(o.CookieSecretFile)
		if err != nil {
			return nil, err
		}
		cookieSecret = string(bs)
	}

	if IsAll(o.Services) && cookieSecret == "" {
		log.WarnCookieSecret()
		cookieSecret = randomSharedKey
	}
	if cookieSecret == "" {
		return nil, errors.New("empty cookie secret")
	}

	return base64.StdEncoding.DecodeString(cookieSecret)
}

// GetCookieSameSite gets the cookie same site option.
func (o *Options) GetCookieSameSite() http.SameSite {
	str := strings.ToLower(o.CookieSameSite)
	switch str {
	case "strict":
		return http.SameSiteStrictMode
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	}
	return http.SameSiteDefaultMode
}

// GetCSRFSameSite gets the csrf same site option.
func (o *Options) GetCSRFSameSite() csrf.SameSiteMode {
	if o.Provider == apple.Name {
		// csrf.SameSiteLaxMode will cause browsers to reset
		// the session on POST. This breaks Appleid being able
		// to verify the csrf token.
		return csrf.SameSiteNoneMode
	}

	str := strings.ToLower(o.CookieSameSite)
	switch str {
	case "strict":
		return csrf.SameSiteStrictMode
	case "lax":
		return csrf.SameSiteLaxMode
	case "none":
		return csrf.SameSiteNoneMode
	}
	return csrf.SameSiteDefaultMode
}

// GetSigningKey gets the signing key.
func (o *Options) GetSigningKey() ([]byte, error) {
	if o == nil {
		return nil, nil
	}

	rawSigningKey := o.SigningKey
	if o.SigningKeyFile != "" {
		bs, err := os.ReadFile(o.SigningKeyFile)
		if err != nil {
			return nil, err
		}
		rawSigningKey = string(bs)
	}

	rawSigningKey = strings.TrimSpace(rawSigningKey)

	if bs, err := base64.StdEncoding.DecodeString(rawSigningKey); err == nil {
		return bs, nil
	}

	return []byte(rawSigningKey), nil
}

// GetAccessLogFields returns the access log fields. If none are set, the default fields are returned.
func (o *Options) GetAccessLogFields() []log.AccessLogField {
	if o.AccessLogFields == nil {
		return log.DefaultAccessLogFields()
	}
	return o.AccessLogFields
}

// GetAuthorizeLogFields returns the authorize log fields. If none are set, the default fields are returned.
func (o *Options) GetAuthorizeLogFields() []log.AuthorizeLogField {
	if o.AuthorizeLogFields == nil {
		return log.DefaultAuthorizeLogFields
	}
	return o.AuthorizeLogFields
}

// NewCookie creates a new Cookie.
func (o *Options) NewCookie() *http.Cookie {
	return &http.Cookie{
		Name:     o.CookieName,
		Domain:   o.CookieDomain,
		Expires:  time.Now().Add(o.CookieExpire),
		Secure:   true,
		SameSite: o.GetCookieSameSite(),
		HttpOnly: o.CookieHTTPOnly,
	}
}

// Checksum returns the checksum of the current options struct
func (o *Options) Checksum() uint64 {
	return hashutil.MustHash(o)
}

func (o *Options) applyExternalCerts(ctx context.Context, certsIndex *cryptutil.CertificatesIndex, certs []*config.Settings_Certificate) {
	for _, c := range certs {
		cert, err := cryptutil.ParsePEMCertificate(c.GetCertBytes())
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("parsing cert from databroker: skipped")
			continue
		}

		if overlaps, name := certsIndex.OverlapsWithExistingCertificate(cert); overlaps {
			log.Ctx(ctx).Error().Err(err).Str("domain", name).Msg("overlaps with local certs: skipped")
			continue
		}

		o.CertificateData = append(o.CertificateData, c)
	}
}

// ApplySettings modifies the config options using the given protobuf settings.
func (o *Options) ApplySettings(ctx context.Context, certsIndex *cryptutil.CertificatesIndex, settings *config.Settings) {
	if settings == nil {
		return
	}

	set(&o.InstallationID, settings.InstallationId)
	setLogLevel(&o.LogLevel, settings.LogLevel)
	setAccessLogFields(&o.AccessLogFields, settings.AccessLogFields)
	setAuthorizeLogFields(&o.AuthorizeLogFields, settings.AuthorizeLogFields)
	setLogLevel(&o.ProxyLogLevel, settings.ProxyLogLevel)
	set(&o.SharedKey, settings.SharedSecret)
	set(&o.Services, settings.Services)
	set(&o.Addr, settings.Address)
	set(&o.InsecureServer, settings.InsecureServer)
	set(&o.DNSLookupFamily, settings.DnsLookupFamily)
	o.applyExternalCerts(ctx, certsIndex, settings.GetCertificates())
	set(&o.HTTPRedirectAddr, settings.HttpRedirectAddr)
	setDuration(&o.ReadTimeout, settings.TimeoutRead)
	setDuration(&o.WriteTimeout, settings.TimeoutWrite)
	setDuration(&o.IdleTimeout, settings.TimeoutIdle)
	set(&o.AuthenticateURLString, settings.AuthenticateServiceUrl)
	set(&o.AuthenticateInternalURLString, settings.AuthenticateInternalServiceUrl)
	set(&o.SignOutRedirectURLString, settings.SignoutRedirectUrl)
	set(&o.AuthenticateCallbackPath, settings.AuthenticateCallbackPath)
	set(&o.CookieName, settings.CookieName)
	set(&o.CookieSecret, settings.CookieSecret)
	set(&o.CookieDomain, settings.CookieDomain)
	set(&o.CookieHTTPOnly, settings.CookieHttpOnly)
	setDuration(&o.CookieExpire, settings.CookieExpire)
	set(&o.CookieSameSite, settings.CookieSameSite)
	set(&o.ClientID, settings.IdpClientId)
	set(&o.ClientSecret, settings.IdpClientSecret)
	set(&o.Provider, settings.IdpProvider)
	set(&o.ProviderURL, settings.IdpProviderUrl)
	setSlice(&o.Scopes, settings.Scopes)
	setMap(&o.RequestParams, settings.RequestParams)
	setStringList(&o.IDPAccessTokenAllowedAudiences, settings.IdpAccessTokenAllowedAudiences)
	setSlice(&o.AuthorizeURLStrings, settings.AuthorizeServiceUrls)
	set(&o.AuthorizeInternalURLString, settings.AuthorizeInternalServiceUrl)
	set(&o.OverrideCertificateName, settings.OverrideCertificateName)
	set(&o.CA, settings.CertificateAuthority)
	setOptional(&o.DeriveInternalDomainCert, settings.DeriveTls)
	set(&o.SigningKey, settings.SigningKey)
	setMap(&o.SetResponseHeaders, settings.SetResponseHeaders)
	setMap(&o.JWTClaimsHeaders, settings.JwtClaimsHeaders)
	setOptional(&o.BearerTokenFormat, BearerTokenFormatFromPB(settings.BearerTokenFormat))
	if len(settings.JwtGroupsFilter) > 0 {
		o.JWTGroupsFilter = NewJWTGroupsFilter(settings.JwtGroupsFilter)
	}
	if f := JWTIssuerFormatFromPB(settings.JwtIssuerFormat); f != JWTIssuerFormatUnset {
		o.JWTIssuerFormat = f
	}
	setDuration(&o.DefaultUpstreamTimeout, settings.DefaultUpstreamTimeout)
	set(&o.MetricsAddr, settings.MetricsAddress)
	set(&o.MetricsBasicAuth, settings.MetricsBasicAuth)
	setCertificate(&o.MetricsCertificate, &o.MetricsCertificateKey, settings.MetricsCertificate)
	set(&o.MetricsClientCA, settings.MetricsClientCa)

	setOptional(&o.Tracing.OtelTracesExporter, settings.OtelTracesExporter)
	setOptional(&o.Tracing.OtelTracesSamplerArg, settings.OtelTracesSamplerArg)
	setSlice(&o.Tracing.OtelResourceAttributes, settings.OtelResourceAttributes)
	setOptional(&o.Tracing.OtelLogLevel, settings.OtelLogLevel)
	setOptional(&o.Tracing.OtelAttributeValueLengthLimit, settings.OtelAttributeValueLengthLimit)
	setOptional(&o.Tracing.OtelExporterOtlpEndpoint, settings.OtelExporterOtlpEndpoint)
	setOptional(&o.Tracing.OtelExporterOtlpTracesEndpoint, settings.OtelExporterOtlpTracesEndpoint)
	setOptional(&o.Tracing.OtelExporterOtlpProtocol, settings.OtelExporterOtlpProtocol)
	setOptional(&o.Tracing.OtelExporterOtlpTracesProtocol, settings.OtelExporterOtlpTracesProtocol)
	setSlice(&o.Tracing.OtelExporterOtlpHeaders, settings.OtelExporterOtlpHeaders)
	setSlice(&o.Tracing.OtelExporterOtlpTracesHeaders, settings.OtelExporterOtlpTracesHeaders)
	setOptionalDuration(&o.Tracing.OtelExporterOtlpTimeout, settings.OtelExporterOtlpTimeout)
	setOptionalDuration(&o.Tracing.OtelExporterOtlpTracesTimeout, settings.OtelExporterOtlpTracesTimeout)
	setOptionalDuration(&o.Tracing.OtelBspScheduleDelay, settings.OtelBspScheduleDelay)
	setOptional(&o.Tracing.OtelBspMaxExportBatchSize, settings.OtelBspMaxExportBatchSize)

	set(&o.GRPCAddr, settings.GrpcAddress)
	setOptional(&o.GRPCInsecure, settings.GrpcInsecure)
	setDuration(&o.GRPCClientTimeout, settings.GrpcClientTimeout)
	setSlice(&o.DataBrokerURLStrings, settings.DatabrokerServiceUrls)
	set(&o.DataBrokerInternalURLString, settings.DatabrokerInternalServiceUrl)
	set(&o.DataBrokerStorageType, settings.DatabrokerStorageType)
	set(&o.DataBrokerStorageConnectionString, settings.DatabrokerStorageConnectionString)
	o.DownstreamMTLS.applySettingsProto(ctx, settings.DownstreamMtls)
	set(&o.GoogleCloudServerlessAuthenticationServiceAccount, settings.GoogleCloudServerlessAuthenticationServiceAccount)
	set(&o.UseProxyProtocol, settings.UseProxyProtocol)
	set(&o.AutocertOptions.Enable, settings.Autocert)
	set(&o.AutocertOptions.CA, settings.AutocertCa)
	set(&o.AutocertOptions.Email, settings.AutocertEmail)
	set(&o.AutocertOptions.EABKeyID, settings.AutocertEabKeyId)
	set(&o.AutocertOptions.EABMACKey, settings.AutocertEabMacKey)
	set(&o.AutocertOptions.UseStaging, settings.AutocertUseStaging)
	set(&o.AutocertOptions.MustStaple, settings.AutocertMustStaple)
	set(&o.AutocertOptions.Folder, settings.AutocertDir)
	set(&o.AutocertOptions.TrustedCA, settings.AutocertTrustedCa)
	set(&o.SkipXffAppend, settings.SkipXffAppend)
	set(&o.XffNumTrustedHops, settings.XffNumTrustedHops)
	set(&o.EnvoyAdminAccessLogPath, settings.EnvoyAdminAccessLogPath)
	set(&o.EnvoyAdminProfilePath, settings.EnvoyAdminProfilePath)
	set(&o.EnvoyAdminAddress, settings.EnvoyAdminAddress)
	set(&o.EnvoyBindConfigSourceAddress, settings.EnvoyBindConfigSourceAddress)
	o.EnvoyBindConfigFreebind = null.BoolFromPtr(settings.EnvoyBindConfigFreebind)
	setSlice(&o.ProgrammaticRedirectDomainWhitelist, settings.ProgrammaticRedirectDomainWhitelist)
	setCodecType(&o.CodecType, settings.CodecType)
	setOptional(&o.PassIdentityHeaders, settings.PassIdentityHeaders)
	if settings.HasBrandingOptions() {
		o.BrandingOptions = settings
	}
	copyMap(&o.RuntimeFlags, settings.RuntimeFlags, func(k string, v bool) (RuntimeFlag, bool) {
		return RuntimeFlag(k), v
	})
	o.HTTP3AdvertisePort = null.Uint32FromPtr(settings.Http3AdvertisePort)
	if settings.CircuitBreakerThresholds != nil {
		o.CircuitBreakerThresholds = CircuitBreakerThresholdsFromPB(settings.CircuitBreakerThresholds)
	}
	set(&o.SSHAddr, settings.SshAddress)
	setStringList(&o.SSHHostKeyFiles, settings.SshHostKeyFiles)
	setStringList(&o.SSHHostKeys, settings.SshHostKeys)
	set(&o.SSHUserCAKeyFile, settings.SshUserCaKeyFile)
	set(&o.SSHUserCAKey, settings.SshUserCaKey)
}

func (o *Options) ToProto() *config.Config {
	var settings config.Settings
	copySrcToOptionalDest(&settings.InstallationId, &o.InstallationID)
	copySrcToOptionalDest(&settings.LogLevel, (*string)(&o.LogLevel))
	settings.AccessLogFields = toStringList(o.AccessLogFields)
	settings.AuthorizeLogFields = toStringList(o.AuthorizeLogFields)
	copySrcToOptionalDest(&settings.ProxyLogLevel, (*string)(&o.ProxyLogLevel))
	copySrcToOptionalDest(&settings.SharedSecret, valueOrFromFileBase64(o.SharedKey, o.SharedSecretFile))
	copySrcToOptionalDest(&settings.Services, &o.Services)
	copySrcToOptionalDest(&settings.Address, &o.Addr)
	copySrcToOptionalDest(&settings.InsecureServer, &o.InsecureServer)
	copySrcToOptionalDest(&settings.DnsLookupFamily, &o.DNSLookupFamily)
	settings.Certificates = getCertificates(o)
	copySrcToOptionalDest(&settings.HttpRedirectAddr, &o.HTTPRedirectAddr)
	copyOptionalDuration(&settings.TimeoutRead, o.ReadTimeout)
	copyOptionalDuration(&settings.TimeoutWrite, o.WriteTimeout)
	copyOptionalDuration(&settings.TimeoutIdle, o.IdleTimeout)
	copySrcToOptionalDest(&settings.AuthenticateServiceUrl, &o.AuthenticateURLString)
	copySrcToOptionalDest(&settings.AuthenticateInternalServiceUrl, &o.AuthenticateInternalURLString)
	copySrcToOptionalDest(&settings.SignoutRedirectUrl, &o.SignOutRedirectURLString)
	copySrcToOptionalDest(&settings.AuthenticateCallbackPath, &o.AuthenticateCallbackPath)
	copySrcToOptionalDest(&settings.CookieName, &o.CookieName)
	copySrcToOptionalDest(&settings.CookieSecret, valueOrFromFileBase64(o.CookieSecret, o.CookieSecretFile))
	copySrcToOptionalDest(&settings.CookieDomain, &o.CookieDomain)
	copySrcToOptionalDest(&settings.CookieHttpOnly, &o.CookieHTTPOnly)
	copyOptionalDuration(&settings.CookieExpire, o.CookieExpire)
	copySrcToOptionalDest(&settings.CookieSameSite, &o.CookieSameSite)
	copySrcToOptionalDest(&settings.IdpClientId, &o.ClientID)
	copySrcToOptionalDest(&settings.IdpClientSecret, valueOrFromFileBase64(o.ClientSecret, o.ClientSecretFile))
	copySrcToOptionalDest(&settings.IdpProvider, &o.Provider)
	copySrcToOptionalDest(&settings.IdpProviderUrl, &o.ProviderURL)
	settings.Scopes = o.Scopes
	settings.RequestParams = o.RequestParams
	copyOptionalStringList(&settings.IdpAccessTokenAllowedAudiences, o.IDPAccessTokenAllowedAudiences)
	settings.AuthorizeServiceUrls = o.AuthorizeURLStrings
	copySrcToOptionalDest(&settings.AuthorizeInternalServiceUrl, &o.AuthorizeInternalURLString)
	copySrcToOptionalDest(&settings.OverrideCertificateName, &o.OverrideCertificateName)
	copySrcToOptionalDest(&settings.CertificateAuthority, valueOrFromFileBase64(o.CA, o.CAFile))
	settings.DeriveTls = o.DeriveInternalDomainCert
	copySrcToOptionalDest(&settings.SigningKey, valueOrFromFileBase64(o.SigningKey, o.SigningKeyFile))
	settings.SetResponseHeaders = o.SetResponseHeaders
	settings.JwtClaimsHeaders = o.JWTClaimsHeaders
	settings.BearerTokenFormat = o.BearerTokenFormat.ToPB()
	settings.JwtGroupsFilter = o.JWTGroupsFilter.ToSlice()
	settings.JwtIssuerFormat = o.JWTIssuerFormat.ToPB()
	copyOptionalDuration(&settings.DefaultUpstreamTimeout, o.DefaultUpstreamTimeout)
	copySrcToOptionalDest(&settings.MetricsAddress, &o.MetricsAddr)
	copySrcToOptionalDest(&settings.MetricsBasicAuth, &o.MetricsBasicAuth)
	settings.MetricsCertificate = toCertificateOrFromFile(o.MetricsCertificate, o.MetricsCertificateKey, o.MetricsCertificateFile, o.MetricsCertificateKeyFile)
	copySrcToOptionalDest(&settings.MetricsClientCa, valueOrFromFileBase64(o.MetricsClientCA, o.MetricsClientCAFile))

	settings.OtelTracesExporter = o.Tracing.OtelTracesExporter
	settings.OtelTracesSamplerArg = o.Tracing.OtelTracesSamplerArg
	settings.OtelResourceAttributes = o.Tracing.OtelResourceAttributes
	settings.OtelLogLevel = o.Tracing.OtelLogLevel
	settings.OtelAttributeValueLengthLimit = o.Tracing.OtelAttributeValueLengthLimit
	settings.OtelExporterOtlpEndpoint = o.Tracing.OtelExporterOtlpEndpoint
	settings.OtelExporterOtlpTracesEndpoint = o.Tracing.OtelExporterOtlpTracesEndpoint
	settings.OtelExporterOtlpProtocol = o.Tracing.OtelExporterOtlpProtocol
	settings.OtelExporterOtlpTracesProtocol = o.Tracing.OtelExporterOtlpTracesProtocol
	settings.OtelExporterOtlpHeaders = o.Tracing.OtelExporterOtlpHeaders
	settings.OtelExporterOtlpTracesHeaders = o.Tracing.OtelExporterOtlpTracesHeaders
	settings.OtelExporterOtlpTimeout = o.Tracing.OtelExporterOtlpTimeout.ToProto()
	settings.OtelExporterOtlpTracesTimeout = o.Tracing.OtelExporterOtlpTracesTimeout.ToProto()
	settings.OtelBspScheduleDelay = o.Tracing.OtelBspScheduleDelay.ToProto()
	settings.OtelBspMaxExportBatchSize = o.Tracing.OtelBspMaxExportBatchSize

	copySrcToOptionalDest(&settings.GrpcAddress, &o.GRPCAddr)
	settings.GrpcInsecure = o.GRPCInsecure
	copyOptionalDuration(&settings.GrpcClientTimeout, o.GRPCClientTimeout)
	settings.DatabrokerServiceUrls = o.DataBrokerURLStrings
	copySrcToOptionalDest(&settings.DatabrokerInternalServiceUrl, &o.DataBrokerInternalURLString)
	copySrcToOptionalDest(&settings.DatabrokerStorageType, &o.DataBrokerStorageType)
	copySrcToOptionalDest(&settings.DatabrokerStorageConnectionString, valueOrFromFileRaw(o.DataBrokerStorageConnectionString, o.DataBrokerStorageConnectionStringFile))
	settings.DownstreamMtls = o.DownstreamMTLS.ToProto()
	copySrcToOptionalDest(&settings.GoogleCloudServerlessAuthenticationServiceAccount, &o.GoogleCloudServerlessAuthenticationServiceAccount)
	copySrcToOptionalDest(&settings.UseProxyProtocol, &o.UseProxyProtocol)
	copySrcToOptionalDest(&settings.Autocert, &o.AutocertOptions.Enable)
	copySrcToOptionalDest(&settings.AutocertCa, &o.AutocertOptions.CA)
	copySrcToOptionalDest(&settings.AutocertEmail, &o.AutocertOptions.Email)
	copySrcToOptionalDest(&settings.AutocertEabKeyId, &o.AutocertOptions.EABKeyID)
	copySrcToOptionalDest(&settings.AutocertEabMacKey, &o.AutocertOptions.EABMACKey)
	copySrcToOptionalDest(&settings.AutocertDir, &o.AutocertOptions.Folder)
	copySrcToOptionalDest(&settings.AutocertTrustedCa, &o.AutocertOptions.TrustedCA)
	copySrcToOptionalDest(&settings.AutocertUseStaging, &o.AutocertOptions.UseStaging)
	copySrcToOptionalDest(&settings.AutocertMustStaple, &o.AutocertOptions.MustStaple)
	copySrcToOptionalDest(&settings.SkipXffAppend, &o.SkipXffAppend)
	copySrcToOptionalDest(&settings.XffNumTrustedHops, &o.XffNumTrustedHops)
	copySrcToOptionalDest(&settings.EnvoyAdminAccessLogPath, &o.EnvoyAdminAccessLogPath)
	copySrcToOptionalDest(&settings.EnvoyAdminProfilePath, &o.EnvoyAdminProfilePath)
	copySrcToOptionalDest(&settings.EnvoyAdminAddress, &o.EnvoyAdminAddress)
	copySrcToOptionalDest(&settings.EnvoyBindConfigSourceAddress, &o.EnvoyBindConfigSourceAddress)
	settings.EnvoyBindConfigFreebind = o.EnvoyBindConfigFreebind.Ptr()
	settings.ProgrammaticRedirectDomainWhitelist = o.ProgrammaticRedirectDomainWhitelist
	if o.CodecType != "" {
		codecType := o.CodecType.ToEnvoy()
		settings.CodecType = &codecType
	}
	settings.PassIdentityHeaders = o.PassIdentityHeaders
	if o.BrandingOptions != nil {
		primaryColor := o.BrandingOptions.GetPrimaryColor()
		secondaryColor := o.BrandingOptions.GetSecondaryColor()
		darkmodePrimaryColor := o.BrandingOptions.GetDarkmodePrimaryColor()
		darkmodeSecondaryColor := o.BrandingOptions.GetDarkmodeSecondaryColor()
		logoURL := o.BrandingOptions.GetLogoUrl()
		faviconURL := o.BrandingOptions.GetFaviconUrl()
		errorMessageFirstParagraph := o.BrandingOptions.GetErrorMessageFirstParagraph()
		copySrcToOptionalDest(&settings.PrimaryColor, &primaryColor)
		copySrcToOptionalDest(&settings.SecondaryColor, &secondaryColor)
		copySrcToOptionalDest(&settings.DarkmodePrimaryColor, &darkmodePrimaryColor)
		copySrcToOptionalDest(&settings.DarkmodeSecondaryColor, &darkmodeSecondaryColor)
		copySrcToOptionalDest(&settings.LogoUrl, &logoURL)
		copySrcToOptionalDest(&settings.FaviconUrl, &faviconURL)
		copySrcToOptionalDest(&settings.ErrorMessageFirstParagraph, &errorMessageFirstParagraph)
	}
	copyMap(&settings.RuntimeFlags, o.RuntimeFlags, func(k RuntimeFlag, v bool) (string, bool) {
		return string(k), v
	})
	settings.Http3AdvertisePort = o.HTTP3AdvertisePort.Ptr()
	if o.CircuitBreakerThresholds != nil {
		settings.CircuitBreakerThresholds = CircuitBreakerThresholdsToPB(o.CircuitBreakerThresholds)
	}
	copySrcToOptionalDest(&settings.SshAddress, &o.SSHAddr)
	copyOptionalStringList(&settings.SshHostKeyFiles, o.SSHHostKeyFiles)
	copyOptionalStringList(&settings.SshHostKeys, o.SSHHostKeys)
	copySrcToOptionalDest(&settings.SshUserCaKeyFile, &o.SSHUserCAKeyFile)
	copySrcToOptionalDest(&settings.SshUserCaKey, &o.SSHUserCAKey)

	routes := make([]*config.Route, 0, o.NumPolicies())
	for p := range o.GetAllPolicies() {
		routepb, err := p.ToProto()
		if err != nil {
			continue
		}
		ppl := p.ToPPL()
		pplIsEmpty := true
		for _, rule := range ppl.Rules {
			if rule.Action == parser.ActionAllow &&
				len(rule.And) > 0 ||
				len(rule.Nor) > 0 ||
				len(rule.Not) > 0 ||
				len(rule.Or) > 0 {
				pplIsEmpty = false
				break
			}
		}
		if !pplIsEmpty {
			raw, err := ppl.MarshalJSON()
			if err != nil {
				continue
			}
			routepb.PplPolicies = append(routepb.PplPolicies, &config.PPLPolicy{
				Raw: raw,
			})
		}
		routes = append(routes, routepb)
	}
	return &config.Config{
		Settings: &settings,
		Routes:   routes,
	}
}

func copySrcToOptionalDest[T comparable](dst **T, src *T) {
	var zero T
	if *src == zero {
		*dst = nil
	} else {
		if *dst == nil {
			*dst = src
		} else {
			**dst = *src
		}
	}
}

func toStringList[T ~string](s []T) *config.Settings_StringList {
	if len(s) == 0 {
		return nil
	}
	strings := make([]string, len(s))
	for i, v := range s {
		strings[i] = string(v)
	}
	return &config.Settings_StringList{Values: strings}
}

func toCertificateOrFromFile(
	cert string, key string,
	certFile string, keyFile string,
) *config.Settings_Certificate {
	var out config.Settings_Certificate
	if cert != "" {
		out.CertBytes, _ = base64.StdEncoding.DecodeString(cert)
	} else if certFile != "" {
		b, err := os.ReadFile(certFile)
		if err == nil {
			out.CertBytes = b
		}
	}

	if key != "" {
		out.KeyBytes, _ = base64.StdEncoding.DecodeString(key)
	} else if keyFile != "" {
		b, err := os.ReadFile(keyFile)
		if err == nil {
			out.KeyBytes = b
		}
	}

	if out.CertBytes == nil && out.KeyBytes == nil {
		return nil
	}
	return &out
}

func getCertificates(o *Options) []*config.Settings_Certificate {
	certs, err := o.GetCertificates()
	if err != nil {
		return nil
	}
	out := make([]*config.Settings_Certificate, len(certs))
	for i, crt := range certs {
		certBytes, keyBytes, err := cryptutil.EncodeCertificate(&crt)
		if err != nil {
			return nil
		}
		out[i] = &config.Settings_Certificate{
			CertBytes: certBytes,
			KeyBytes:  keyBytes,
		}
	}
	return out
}

func copyOptionalDuration(dst **durationpb.Duration, src time.Duration) {
	if src == 0 {
		*dst = nil
	} else {
		*dst = durationpb.New(src)
	}
}

func copyOptionalStringList(dst **config.Settings_StringList, src *[]string) {
	if src == nil {
		*dst = nil
	} else {
		*dst = &config.Settings_StringList{Values: slices.Clone(*src)}
	}
}

func valueOrFromFileRaw(value string, valueFile string) *string {
	if value != "" {
		return &value
	}
	if valueFile == "" {
		return &valueFile
	}
	data, _ := os.ReadFile(valueFile)
	dataStr := string(data)
	return &dataStr
}

func valueOrFromFileBase64(value string, valueFile string) *string {
	if value != "" {
		return &value
	}
	if valueFile == "" {
		return &valueFile
	}
	data, _ := os.ReadFile(valueFile)
	encoded := base64.StdEncoding.EncodeToString(data)
	return &encoded
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

// NewAtomicOptions creates a new AtomicOptions.
func NewAtomicOptions() *atomicutil.Value[*Options] {
	return atomicutil.NewValue(new(Options))
}

func set[T any](dst, src *T) {
	if src == nil {
		return
	}
	*dst = *src
}

func setAccessLogFields(dst *[]log.AccessLogField, src *config.Settings_StringList) {
	if src == nil {
		return
	}
	*dst = make([]log.AccessLogField, len(src.Values))
	for i, v := range src.Values {
		(*dst)[i] = log.AccessLogField(v)
	}
}

func setAuthorizeLogFields(dst *[]log.AuthorizeLogField, src *config.Settings_StringList) {
	if src == nil {
		return
	}
	*dst = make([]log.AuthorizeLogField, len(src.Values))
	for i, v := range src.Values {
		(*dst)[i] = log.AuthorizeLogField(v)
	}
}

func setCodecType(dst *CodecType, src *envoy_http_connection_manager.HttpConnectionManager_CodecType) {
	if src == nil {
		return
	}
	*dst = CodecTypeFromEnvoy(*src)
}

func setDuration(dst *time.Duration, src *durationpb.Duration) {
	if src == nil {
		return
	}
	*dst = src.AsDuration()
}

func setOptionalDuration[T ~int64](dst **T, src *durationpb.Duration) {
	if src == nil {
		return
	}
	v := T(src.AsDuration())
	*dst = &v
}

func setLogLevel(dst *LogLevel, src *string) {
	if src == nil {
		return
	}
	*dst = LogLevel(*src)
}

func setOptional[T any](dst **T, src *T) {
	if src == nil {
		return
	}
	v := *src
	*dst = &v
}

func setSlice[T any](dst *[]T, src []T) {
	if len(src) == 0 {
		return
	}
	*dst = src
}

func setStringList(dst **[]string, src *config.Settings_StringList) {
	if src == nil {
		return
	}
	values := slices.Clone(src.Values)
	*dst = &values
}

func setMap[TKey comparable, TValue any, TMap ~map[TKey]TValue](dst *TMap, src map[TKey]TValue) {
	if len(src) == 0 {
		return
	}
	*dst = src
}

func copyMap[T1Key comparable, T1Value any, T2Key comparable, T2Value any, TMap1 ~map[T1Key]T1Value, TMap2 ~map[T2Key]T2Value](
	dst *TMap1,
	src TMap2,
	convert func(T2Key, T2Value) (T1Key, T1Value),
) {
	if len(src) == 0 {
		return
	}
	*dst = make(TMap1, len(src))
	for k, v := range src {
		k1, v1 := convert(k, v)
		(*dst)[k1] = v1
	}
}

func setCertificate(
	dstCertificate *string,
	dstCertificateKey *string,
	src *config.Settings_Certificate,
) {
	if src == nil {
		return
	}
	if len(src.GetCertBytes()) > 0 {
		*dstCertificate = base64.StdEncoding.EncodeToString(src.GetCertBytes())
	}
	if len(src.GetKeyBytes()) > 0 {
		*dstCertificateKey = base64.StdEncoding.EncodeToString(src.GetKeyBytes())
	}
}
