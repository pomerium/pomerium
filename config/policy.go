package config

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/golang/protobuf/ptypes"

	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// Policy contains route specific configuration and access settings.
type Policy struct {
	From string      `mapstructure:"from" yaml:"from"`
	To   StringSlice `mapstructure:"to" yaml:"to"`

	// Redirect is used for a redirect action instead of `To`
	Redirect *PolicyRedirect `mapstructure:"redirect" yaml:"redirect"`

	// Identity related policy
	AllowedUsers     []string                 `mapstructure:"allowed_users" yaml:"allowed_users,omitempty" json:"allowed_users,omitempty"`
	AllowedGroups    []string                 `mapstructure:"allowed_groups" yaml:"allowed_groups,omitempty" json:"allowed_groups,omitempty"`
	AllowedDomains   []string                 `mapstructure:"allowed_domains" yaml:"allowed_domains,omitempty" json:"allowed_domains,omitempty"`
	AllowedIDPClaims identity.FlattenedClaims `mapstructure:"allowed_idp_claims" yaml:"allowed_idp_claims,omitempty" json:"allowed_idp_claims,omitempty"`

	Source       *StringURL `yaml:",omitempty" json:"source,omitempty" hash:"ignore"`
	Destinations []*url.URL `yaml:",omitempty" json:"destinations,omitempty" hash:"ignore"`

	// Additional route matching options
	Prefix string `mapstructure:"prefix" yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Path   string `mapstructure:"path" yaml:"path,omitempty" json:"path,omitempty"`
	Regex  string `mapstructure:"regex" yaml:"regex,omitempty" json:"regex,omitempty"`

	// Path Rewrite Options
	PrefixRewrite            string `mapstructure:"prefix_rewrite" yaml:"prefix_rewrite,omitempty" json:"prefix_rewrite,omitempty"`
	RegexRewritePattern      string `mapstructure:"regex_rewrite_pattern" yaml:"regex_rewrite_pattern,omitempty" json:"regex_rewrite_pattern,omitempty"`
	RegexRewriteSubstitution string `mapstructure:"regex_rewrite_substitution" yaml:"regex_rewrite_substitution,omitempty" json:"regex_rewrite_substitution,omitempty"` //nolint

	// Host Rewrite Options
	HostRewrite                      string `mapstructure:"host_rewrite" yaml:"host_rewrite,omitempty" json:"host_rewrite,omitempty"`
	HostRewriteHeader                string `mapstructure:"host_rewrite_header" yaml:"host_rewrite_header,omitempty" json:"host_rewrite_header,omitempty"`
	HostPathRegexRewritePattern      string `mapstructure:"host_path_regex_rewrite_pattern" yaml:"host_path_regex_rewrite_pattern,omitempty" json:"host_path_regex_rewrite_pattern,omitempty"`                //nolint
	HostPathRegexRewriteSubstitution string `mapstructure:"host_path_regex_rewrite_substitution" yaml:"host_path_regex_rewrite_substitution,omitempty" json:"host_path_regex_rewrite_substitution,omitempty"` //nolint

	// Allow unauthenticated HTTP OPTIONS requests as per the CORS spec
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#Preflighted_requests
	CORSAllowPreflight bool `mapstructure:"cors_allow_preflight" yaml:"cors_allow_preflight,omitempty"`

	// Allow any public request to access this route. **Bypasses authentication**
	AllowPublicUnauthenticatedAccess bool `mapstructure:"allow_public_unauthenticated_access" yaml:"allow_public_unauthenticated_access,omitempty"`

	// Allow any authenticated user
	AllowAnyAuthenticatedUser bool `mapstructure:"allow_any_authenticated_user" yaml:"allow_any_authenticated_user,omitempty"`

	// UpstreamTimeout is the route specific timeout. Must be less than the global
	// timeout. If unset,  route will fallback to the proxy's DefaultUpstreamTimeout.
	UpstreamTimeout time.Duration `mapstructure:"timeout" yaml:"timeout,omitempty"`

	// Enable proxying of websocket connections by removing the default timeout handler.
	// Caution: Enabling this feature could result in abuse via DOS attacks.
	AllowWebsockets bool `mapstructure:"allow_websockets"  yaml:"allow_websockets,omitempty"`

	// AllowSPDY enables proxying of SPDY upgrade requests
	AllowSPDY bool `mapstructure:"allow_spdy" yaml:"allow_spdy,omitempty"`

	// TLSSkipVerify controls whether a client verifies the server's certificate
	// chain and host name.
	// If TLSSkipVerify is true, TLS accepts any certificate presented by the
	// server and any host name in that certificate.
	// In this mode, TLS is susceptible to man-in-the-middle attacks.
	// This should be used only for testing.
	TLSSkipVerify bool `mapstructure:"tls_skip_verify" yaml:"tls_skip_verify,omitempty"`

	// TLSServerName overrides the hostname in the `to` field. This is useful
	// if your backend is an HTTPS server with a valid certificate, but you
	// want to communicate to the backend with an internal hostname (e.g.
	// Docker container name).
	TLSServerName string `mapstructure:"tls_server_name" yaml:"tls_server_name,omitempty"`

	// TLSCustomCA defines the  root certificate to use with a given
	// route when verifying server certificates.
	TLSCustomCA     string `mapstructure:"tls_custom_ca" yaml:"tls_custom_ca,omitempty"`
	TLSCustomCAFile string `mapstructure:"tls_custom_ca_file" yaml:"tls_custom_ca_file,omitempty"`

	// Contains the x.509 client certificate to present to the downstream
	// host.
	TLSClientCert     string           `mapstructure:"tls_client_cert" yaml:"tls_client_cert,omitempty"`
	TLSClientKey      string           `mapstructure:"tls_client_key" yaml:"tls_client_key,omitempty"`
	TLSClientCertFile string           `mapstructure:"tls_client_cert_file" yaml:"tls_client_cert_file,omitempty"`
	TLSClientKeyFile  string           `mapstructure:"tls_client_key_file" yaml:"tls_client_key_file,omitempty"`
	ClientCertificate *tls.Certificate `yaml:",omitempty" hash:"ignore"`

	// SetRequestHeaders adds a collection of headers to the downstream request
	// in the form of key value pairs. Note bene, this will overwrite the
	// value of any existing value of a given header key.
	SetRequestHeaders map[string]string `mapstructure:"set_request_headers" yaml:"set_request_headers,omitempty"`

	// RemoveRequestHeaders removes a collection of headers from a downstream request.
	// Note that this has lower priority than `SetRequestHeaders`, if you specify `X-Custom-Header` in both
	// `SetRequestHeaders` and `RemoveRequestHeaders`, then the header won't be removed.
	RemoveRequestHeaders []string `mapstructure:"remove_request_headers" yaml:"remove_request_headers,omitempty"`

	// PreserveHostHeader disables host header rewriting.
	//
	// This option only takes affect if the destination is a DNS name. If the destination is an IP address,
	// use SetRequestHeaders to explicitly set the "Host" header.
	//
	// https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header
	PreserveHostHeader bool `mapstructure:"preserve_host_header" yaml:"preserve_host_header,omitempty"`

	// PassIdentityHeaders controls whether to add a user's identity headers to the downstream request.
	// These includes:
	//
	//  - X-Pomerium-Jwt-Assertion
	//  - X-Pomerium-Claim-*
	//
	PassIdentityHeaders bool `mapstructure:"pass_identity_headers" yaml:"pass_identity_headers,omitempty"`

	// KubernetesServiceAccountToken is the kubernetes token to use for upstream requests.
	KubernetesServiceAccountToken string `mapstructure:"kubernetes_service_account_token" yaml:"kubernetes_service_account_token,omitempty"`
	// KubernetesServiceAccountTokenFile contains the kubernetes token to use for upstream requests.
	KubernetesServiceAccountTokenFile string `mapstructure:"kubernetes_service_account_token_file" yaml:"kubernetes_service_account_token_file,omitempty"`

	// EnableGoogleCloudServerlessAuthentication adds "Authorization: Bearer ID_TOKEN" headers
	// to upstream requests.
	EnableGoogleCloudServerlessAuthentication bool `mapstructure:"enable_google_cloud_serverless_authentication" yaml:"enable_google_cloud_serverless_authentication,omitempty"` //nolint

	// OutlierDetection configures outlier detection for the upstream cluster.
	OutlierDetection *PolicyOutlierDetection `mapstructure:"outlier_detection" yaml:"outlier_detection,omitempty" json:"outlier_detection,omitempty"`

	SubPolicies []SubPolicy `mapstructure:"sub_policies" yaml:"sub_policies,omitempty" json:"sub_policies,omitempty"`
}

// A SubPolicy is a protobuf Policy within a protobuf Route.
type SubPolicy struct {
	ID               string                   `mapstructure:"id" yaml:"id" json:"id"`
	Name             string                   `mapstructure:"name" yaml:"name" json:"name"`
	AllowedUsers     []string                 `mapstructure:"allowed_users" yaml:"allowed_users,omitempty" json:"allowed_users,omitempty"`
	AllowedGroups    []string                 `mapstructure:"allowed_groups" yaml:"allowed_groups,omitempty" json:"allowed_groups,omitempty"`
	AllowedDomains   []string                 `mapstructure:"allowed_domains" yaml:"allowed_domains,omitempty" json:"allowed_domains,omitempty"`
	AllowedIDPClaims identity.FlattenedClaims `mapstructure:"allowed_idp_claims" yaml:"allowed_idp_claims,omitempty" json:"allowed_idp_claims,omitempty"`
	Rego             []string                 `mapstructure:"rego" yaml:"rego" json:"rego,omitempty"`
}

// PolicyRedirect is a route redirect action.
type PolicyRedirect struct {
	HTTPSRedirect  *bool   `mapstructure:"https_redirect" yaml:"https_redirect,omitempty" json:"https_redirect,omitempty"`
	SchemeRedirect *string `mapstructure:"scheme_redirect" yaml:"scheme_redirect,omitempty" json:"scheme_redirect,omitempty"`
	HostRedirect   *string `mapstructure:"host_redirect" yaml:"host_redirect,omitempty" json:"host_redirect,omitempty"`
	PortRedirect   *uint32 `mapstructure:"port_redirect" yaml:"port_redirect,omitempty" json:"port_redirect,omitempty"`
	PathRedirect   *string `mapstructure:"path_redirect" yaml:"path_redirect,omitempty" json:"path_redirect,omitempty"`
	PrefixRewrite  *string `mapstructure:"prefix_rewrite" yaml:"prefix_rewrite,omitempty" json:"prefix_rewrite,omitempty"`
	ResponseCode   *int32  `mapstructure:"response_code" yaml:"response_code,omitempty" json:"response_code,omitempty"`
	StripQuery     *bool   `mapstructure:"strip_query" yaml:"strip_query,omitempty" json:"strip_query,omitempty"`
}

type PolicyOutlierDetection envoy_config_cluster_v3.OutlierDetection

// NewPolicyFromProto creates a new Policy from a protobuf policy config route.
func NewPolicyFromProto(pb *configpb.Route) (*Policy, error) {
	timeout, _ := ptypes.Duration(pb.GetTimeout())

	p := &Policy{
		From:                             pb.GetFrom(),
		To:                               NewStringSlice(pb.GetTo()...),
		AllowedUsers:                     pb.GetAllowedUsers(),
		AllowedGroups:                    pb.GetAllowedGroups(),
		AllowedDomains:                   pb.GetAllowedDomains(),
		AllowedIDPClaims:                 identity.NewFlattenedClaimsFromPB(pb.GetAllowedIdpClaims()),
		Prefix:                           pb.GetPrefix(),
		Path:                             pb.GetPath(),
		Regex:                            pb.GetRegex(),
		PrefixRewrite:                    pb.GetPrefixRewrite(),
		RegexRewritePattern:              pb.GetRegexRewritePattern(),
		RegexRewriteSubstitution:         pb.GetRegexRewriteSubstitution(),
		CORSAllowPreflight:               pb.GetCorsAllowPreflight(),
		AllowPublicUnauthenticatedAccess: pb.GetAllowPublicUnauthenticatedAccess(),
		AllowAnyAuthenticatedUser:        pb.GetAllowAnyAuthenticatedUser(),
		UpstreamTimeout:                  timeout,
		AllowWebsockets:                  pb.GetAllowWebsockets(),
		TLSSkipVerify:                    pb.GetTlsSkipVerify(),
		TLSServerName:                    pb.GetTlsServerName(),
		TLSCustomCA:                      pb.GetTlsCustomCa(),
		TLSCustomCAFile:                  pb.GetTlsCustomCaFile(),
		TLSClientCert:                    pb.GetTlsClientCert(),
		TLSClientKey:                     pb.GetTlsClientKey(),
		TLSClientCertFile:                pb.GetTlsClientCertFile(),
		TLSClientKeyFile:                 pb.GetTlsClientKeyFile(),
		SetRequestHeaders:                pb.GetSetRequestHeaders(),
		RemoveRequestHeaders:             pb.GetRemoveRequestHeaders(),
		PreserveHostHeader:               pb.GetPreserveHostHeader(),
		PassIdentityHeaders:              pb.GetPassIdentityHeaders(),
		KubernetesServiceAccountToken:    pb.GetKubernetesServiceAccountToken(),
	}
	if pb.Redirect != nil {
		p.Redirect = &PolicyRedirect{
			HTTPSRedirect:  pb.Redirect.HttpsRedirect,
			SchemeRedirect: pb.Redirect.SchemeRedirect,
			HostRedirect:   pb.Redirect.HostRedirect,
			PortRedirect:   pb.Redirect.PortRedirect,
			PathRedirect:   pb.Redirect.PathRedirect,
			PrefixRewrite:  pb.Redirect.PrefixRewrite,
			ResponseCode:   pb.Redirect.ResponseCode,
			StripQuery:     pb.Redirect.StripQuery,
		}
	}
	if pb.OutlierDetection != nil {
		p.OutlierDetection = &PolicyOutlierDetection{
			Consecutive_5Xx:                        pb.OutlierDetection.Consecutive_5Xx,
			Interval:                               pb.OutlierDetection.Interval,
			BaseEjectionTime:                       pb.OutlierDetection.BaseEjectionTime,
			MaxEjectionPercent:                     pb.OutlierDetection.MaxEjectionPercent,
			EnforcingConsecutive_5Xx:               pb.OutlierDetection.EnforcingConsecutive_5Xx,
			EnforcingSuccessRate:                   pb.OutlierDetection.EnforcingSuccessRate,
			SuccessRateMinimumHosts:                pb.OutlierDetection.SuccessRateMinimumHosts,
			SuccessRateRequestVolume:               pb.OutlierDetection.SuccessRateRequestVolume,
			SuccessRateStdevFactor:                 pb.OutlierDetection.SuccessRateStdevFactor,
			ConsecutiveGatewayFailure:              pb.OutlierDetection.ConsecutiveGatewayFailure,
			EnforcingConsecutiveGatewayFailure:     pb.OutlierDetection.EnforcingConsecutiveGatewayFailure,
			SplitExternalLocalOriginErrors:         pb.OutlierDetection.SplitExternalLocalOriginErrors,
			ConsecutiveLocalOriginFailure:          pb.OutlierDetection.ConsecutiveLocalOriginFailure,
			EnforcingConsecutiveLocalOriginFailure: pb.OutlierDetection.EnforcingConsecutiveLocalOriginFailure,
			EnforcingLocalOriginSuccessRate:        pb.OutlierDetection.EnforcingLocalOriginSuccessRate,
			FailurePercentageThreshold:             pb.OutlierDetection.FailurePercentageThreshold,
			EnforcingFailurePercentage:             pb.OutlierDetection.EnforcingFailurePercentage,
			EnforcingFailurePercentageLocalOrigin:  pb.OutlierDetection.EnforcingFailurePercentageLocalOrigin,
			FailurePercentageMinimumHosts:          pb.OutlierDetection.FailurePercentageMinimumHosts,
			FailurePercentageRequestVolume:         pb.OutlierDetection.FailurePercentageRequestVolume,
		}
	}
	for _, sp := range pb.GetPolicies() {
		p.SubPolicies = append(p.SubPolicies, SubPolicy{
			ID:               sp.GetId(),
			Name:             sp.GetName(),
			AllowedUsers:     sp.GetAllowedUsers(),
			AllowedGroups:    sp.GetAllowedGroups(),
			AllowedDomains:   sp.GetAllowedDomains(),
			AllowedIDPClaims: identity.NewFlattenedClaimsFromPB(sp.GetAllowedIdpClaims()),
			Rego:             sp.GetRego(),
		})
	}
	return p, p.Validate()
}

// ToProto converts the policy to a protobuf type.
func (p *Policy) ToProto() *configpb.Route {
	timeout := ptypes.DurationProto(p.UpstreamTimeout)
	sps := make([]*configpb.Policy, 0, len(p.SubPolicies))
	for _, sp := range p.SubPolicies {
		sps = append(sps, &configpb.Policy{
			Id:               sp.ID,
			Name:             sp.Name,
			AllowedUsers:     sp.AllowedUsers,
			AllowedGroups:    sp.AllowedGroups,
			AllowedDomains:   sp.AllowedDomains,
			AllowedIdpClaims: sp.AllowedIDPClaims.ToPB(),
			Rego:             sp.Rego,
		})
	}
	pb := &configpb.Route{
		Name:                             fmt.Sprint(p.RouteID()),
		From:                             p.From,
		To:                               p.To,
		AllowedUsers:                     p.AllowedUsers,
		AllowedGroups:                    p.AllowedGroups,
		AllowedDomains:                   p.AllowedDomains,
		AllowedIdpClaims:                 p.AllowedIDPClaims.ToPB(),
		Prefix:                           p.Prefix,
		Path:                             p.Path,
		Regex:                            p.Regex,
		PrefixRewrite:                    p.PrefixRewrite,
		RegexRewritePattern:              p.RegexRewritePattern,
		RegexRewriteSubstitution:         p.RegexRewriteSubstitution,
		CorsAllowPreflight:               p.CORSAllowPreflight,
		AllowPublicUnauthenticatedAccess: p.AllowPublicUnauthenticatedAccess,
		AllowAnyAuthenticatedUser:        p.AllowAnyAuthenticatedUser,
		Timeout:                          timeout,
		AllowWebsockets:                  p.AllowWebsockets,
		TlsSkipVerify:                    p.TLSSkipVerify,
		TlsServerName:                    p.TLSServerName,
		TlsCustomCa:                      p.TLSCustomCA,
		TlsCustomCaFile:                  p.TLSCustomCAFile,
		TlsClientCert:                    p.TLSClientCert,
		TlsClientKey:                     p.TLSClientKey,
		TlsClientCertFile:                p.TLSClientCertFile,
		TlsClientKeyFile:                 p.TLSClientKeyFile,
		SetRequestHeaders:                p.SetRequestHeaders,
		RemoveRequestHeaders:             p.RemoveRequestHeaders,
		PreserveHostHeader:               p.PreserveHostHeader,
		PassIdentityHeaders:              p.PassIdentityHeaders,
		KubernetesServiceAccountToken:    p.KubernetesServiceAccountToken,
		Policies:                         sps,
	}
	if p.Redirect != nil {
		pb.Redirect = &configpb.RouteRedirect{
			HttpsRedirect:  p.Redirect.HTTPSRedirect,
			SchemeRedirect: p.Redirect.SchemeRedirect,
			HostRedirect:   p.Redirect.HostRedirect,
			PortRedirect:   p.Redirect.PortRedirect,
			PathRedirect:   p.Redirect.PathRedirect,
			PrefixRewrite:  p.Redirect.PrefixRewrite,
			ResponseCode:   p.Redirect.ResponseCode,
			StripQuery:     p.Redirect.StripQuery,
		}
	}
	if p.OutlierDetection != nil {
		pb.OutlierDetection = &configpb.OutlierDetection{
			Consecutive_5Xx:                        p.OutlierDetection.Consecutive_5Xx,
			Interval:                               p.OutlierDetection.Interval,
			BaseEjectionTime:                       p.OutlierDetection.BaseEjectionTime,
			MaxEjectionPercent:                     p.OutlierDetection.MaxEjectionPercent,
			EnforcingConsecutive_5Xx:               p.OutlierDetection.EnforcingConsecutive_5Xx,
			EnforcingSuccessRate:                   p.OutlierDetection.EnforcingSuccessRate,
			SuccessRateMinimumHosts:                p.OutlierDetection.SuccessRateMinimumHosts,
			SuccessRateRequestVolume:               p.OutlierDetection.SuccessRateRequestVolume,
			SuccessRateStdevFactor:                 p.OutlierDetection.SuccessRateStdevFactor,
			ConsecutiveGatewayFailure:              p.OutlierDetection.ConsecutiveGatewayFailure,
			EnforcingConsecutiveGatewayFailure:     p.OutlierDetection.EnforcingConsecutiveGatewayFailure,
			SplitExternalLocalOriginErrors:         p.OutlierDetection.SplitExternalLocalOriginErrors,
			ConsecutiveLocalOriginFailure:          p.OutlierDetection.ConsecutiveLocalOriginFailure,
			EnforcingConsecutiveLocalOriginFailure: p.OutlierDetection.EnforcingConsecutiveLocalOriginFailure,
			EnforcingLocalOriginSuccessRate:        p.OutlierDetection.EnforcingLocalOriginSuccessRate,
			FailurePercentageThreshold:             p.OutlierDetection.FailurePercentageThreshold,
			EnforcingFailurePercentage:             p.OutlierDetection.EnforcingFailurePercentage,
			EnforcingFailurePercentageLocalOrigin:  p.OutlierDetection.EnforcingFailurePercentageLocalOrigin,
			FailurePercentageMinimumHosts:          p.OutlierDetection.FailurePercentageMinimumHosts,
			FailurePercentageRequestVolume:         p.OutlierDetection.FailurePercentageRequestVolume,
		}
	}
	return pb
}

// Validate checks the validity of a policy.
func (p *Policy) Validate() error {
	var err error
	source, err := urlutil.ParseAndValidateURL(p.From)
	if err != nil {
		return fmt.Errorf("config: policy bad source url %w", err)
	}

	// Make sure there's no path set on the from url
	if (source.Scheme == "http" || source.Scheme == "https") && !(source.Path == "" || source.Path == "/") {
		return fmt.Errorf("config: policy source url (%s) contains a path, but it should be set using the path field instead",
			source.String())
	}

	p.Source = &StringURL{source}

	switch {
	case len(p.To) > 0:
		p.Destinations = nil
		for _, to := range p.To {
			dst, err := urlutil.ParseAndValidateURL(to)
			if err != nil {
				return fmt.Errorf("config: policy bad destination url %w", err)
			}
			p.Destinations = append(p.Destinations, dst)
		}
	case p.Redirect != nil:
	default:
		return fmt.Errorf("config: policy must have either a `to` or `redirect`")
	}

	// Only allow public access if no other whitelists are in place
	if p.AllowPublicUnauthenticatedAccess && (p.AllowAnyAuthenticatedUser || p.AllowedDomains != nil || p.AllowedGroups != nil || p.AllowedUsers != nil) {
		return fmt.Errorf("config: policy route marked as public but contains whitelists")
	}

	// Only allow any authenticated user if no other whitelists are in place
	if p.AllowAnyAuthenticatedUser && (p.AllowedDomains != nil || p.AllowedGroups != nil || p.AllowedUsers != nil) {
		return fmt.Errorf("config: policy route marked accessible for any authenticated user but contains whitelists")
	}

	if (p.TLSClientCert == "" && p.TLSClientKey != "") || (p.TLSClientCert != "" && p.TLSClientKey == "") ||
		(p.TLSClientCertFile == "" && p.TLSClientKeyFile != "") || (p.TLSClientCertFile != "" && p.TLSClientKeyFile == "") {
		return fmt.Errorf("config: client certificate key and cert both must be non-empty")
	}

	if p.TLSClientCert != "" && p.TLSClientKey != "" {
		p.ClientCertificate, err = cryptutil.CertificateFromBase64(p.TLSClientCert, p.TLSClientKey)
		if err != nil {
			return fmt.Errorf("config: couldn't decode client cert %w", err)
		}
	} else if p.TLSClientCertFile != "" && p.TLSClientKeyFile != "" {
		p.ClientCertificate, err = cryptutil.CertificateFromFile(p.TLSClientCertFile, p.TLSClientKeyFile)
		if err != nil {
			return fmt.Errorf("config: couldn't load client cert file %w", err)
		}
	}

	if p.TLSCustomCA != "" {
		_, err := base64.StdEncoding.DecodeString(p.TLSCustomCA)
		if err != nil {
			return fmt.Errorf("config: couldn't decode custom ca: %w", err)
		}
	} else if p.TLSCustomCAFile != "" {
		_, err := os.Stat(p.TLSCustomCAFile)
		if err != nil {
			return fmt.Errorf("config: couldn't load client ca file: %w", err)
		}
	}

	if p.KubernetesServiceAccountTokenFile != "" {
		if p.KubernetesServiceAccountToken != "" {
			return fmt.Errorf("config: specified both `kubernetes_service_account_token_file` and `kubernetes_service_account_token`")
		}

		token, err := ioutil.ReadFile(p.KubernetesServiceAccountTokenFile)
		if err != nil {
			return fmt.Errorf("config: failed to load kubernetes service account token: %w", err)
		}
		p.KubernetesServiceAccountToken = string(token)
	}

	if p.PrefixRewrite != "" && p.RegexRewritePattern != "" {
		return fmt.Errorf("config: only prefix_rewrite or regex_rewrite_pattern can be specified, but not both")
	}

	return nil
}

// Checksum returns the xxhash hash for the policy.
func (p *Policy) Checksum() uint64 {
	return hashutil.MustHash(p)
}

// RouteID returns a unique identifier for a route
func (p *Policy) RouteID() uint64 {
	id := routeID{
		Source:       p.Source,
		Destinations: p.Destinations,
		Prefix:       p.Prefix,
		Path:         p.Path,
		Regex:        p.Regex,
	}

	return hashutil.MustHash(id)
}

func (p *Policy) String() string {
	if p.Source == nil || len(p.Destinations) == 0 {
		return fmt.Sprintf("%s → %s", p.From, strings.Join(p.To, ","))
	}
	var dsts []string
	for _, dst := range p.Destinations {
		dsts = append(dsts, dst.String())
	}
	return fmt.Sprintf("%s → %s", p.Source.String(), strings.Join(dsts, ","))
}

// Matches returns true if the policy would match the given URL.
func (p *Policy) Matches(requestURL *url.URL) bool {
	// handle nils by always returning false
	if p.Source == nil || requestURL == nil {
		return false
	}

	if p.Source.Host != requestURL.Host {
		return false
	}

	if p.Prefix != "" {
		if !strings.HasPrefix(requestURL.Path, p.Prefix) {
			return false
		}
	}

	if p.Path != "" {
		if requestURL.Path != p.Path {
			return false
		}
	}

	if p.Regex != "" {
		re, err := regexp.Compile(p.Regex)
		if err == nil && !re.MatchString(requestURL.String()) {
			return false
		}
	}

	return true
}

// StringURL stores a URL as a string in json.
type StringURL struct {
	*url.URL
}

// MarshalJSON returns the URLs host as json.
func (u *StringURL) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.String())
}

type routeID struct {
	Source       *StringURL
	Destinations []*url.URL
	Prefix       string
	Path         string
	Regex        string
}
