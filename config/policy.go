package config

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cespare/xxhash/v2"
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/valyala/bytebufferpool"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/identity"
)

// Policy contains route specific configuration and access settings.
type Policy struct {
	ID string `mapstructure:"-" yaml:"-" json:"-"`

	From string       `mapstructure:"from" yaml:"from"`
	To   WeightedURLs `mapstructure:"to" yaml:"to"`
	// Redirect is used for a redirect action instead of `To`
	Redirect *PolicyRedirect `mapstructure:"redirect" yaml:"redirect"`
	Response *DirectResponse `mapstructure:"response" yaml:"response,omitempty" json:"response,omitempty"`

	// LbWeights are optional load balancing weights applied to endpoints specified in To
	// this field exists for compatibility with mapstructure
	LbWeights []uint32 `mapstructure:"_to_weights,omitempty" json:"-" yaml:"-"`

	// Identity related policy
	AllowedUsers     []string                 `mapstructure:"allowed_users" yaml:"allowed_users,omitempty" json:"allowed_users,omitempty"`
	AllowedDomains   []string                 `mapstructure:"allowed_domains" yaml:"allowed_domains,omitempty" json:"allowed_domains,omitempty"`
	AllowedIDPClaims identity.FlattenedClaims `mapstructure:"allowed_idp_claims" yaml:"allowed_idp_claims,omitempty" json:"allowed_idp_claims,omitempty"`

	// Additional route matching options
	Prefix             string `mapstructure:"prefix" yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Path               string `mapstructure:"path" yaml:"path,omitempty" json:"path,omitempty"`
	Regex              string `mapstructure:"regex" yaml:"regex,omitempty" json:"regex,omitempty"`
	RegexPriorityOrder *int64 `mapstructure:"regex_priority_order" yaml:"regex_priority_order,omitempty" json:"regex_priority_order,omitempty"`
	compiledRegex      *regexp.Regexp

	// Path Rewrite Options
	PrefixRewrite            string `mapstructure:"prefix_rewrite" yaml:"prefix_rewrite,omitempty" json:"prefix_rewrite,omitempty"`
	RegexRewritePattern      string `mapstructure:"regex_rewrite_pattern" yaml:"regex_rewrite_pattern,omitempty" json:"regex_rewrite_pattern,omitempty"`
	RegexRewriteSubstitution string `mapstructure:"regex_rewrite_substitution" yaml:"regex_rewrite_substitution,omitempty" json:"regex_rewrite_substitution,omitempty"`

	// Host Rewrite Options
	HostRewrite                      string `mapstructure:"host_rewrite" yaml:"host_rewrite,omitempty" json:"host_rewrite,omitempty"`
	HostRewriteHeader                string `mapstructure:"host_rewrite_header" yaml:"host_rewrite_header,omitempty" json:"host_rewrite_header,omitempty"`
	HostPathRegexRewritePattern      string `mapstructure:"host_path_regex_rewrite_pattern" yaml:"host_path_regex_rewrite_pattern,omitempty" json:"host_path_regex_rewrite_pattern,omitempty"`
	HostPathRegexRewriteSubstitution string `mapstructure:"host_path_regex_rewrite_substitution" yaml:"host_path_regex_rewrite_substitution,omitempty" json:"host_path_regex_rewrite_substitution,omitempty"`

	// Allow unauthenticated HTTP OPTIONS requests as per the CORS spec
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#Preflighted_requests
	CORSAllowPreflight bool `mapstructure:"cors_allow_preflight" yaml:"cors_allow_preflight,omitempty"`

	// Allow any public request to access this route. **Bypasses authentication**
	AllowPublicUnauthenticatedAccess bool `mapstructure:"allow_public_unauthenticated_access" yaml:"allow_public_unauthenticated_access,omitempty"`

	// Allow any authenticated user
	AllowAnyAuthenticatedUser bool `mapstructure:"allow_any_authenticated_user" yaml:"allow_any_authenticated_user,omitempty"`

	// UpstreamTimeout is the route specific timeout. Must be less than the global
	// timeout. If unset, route will fallback to the proxy's DefaultUpstreamTimeout.
	UpstreamTimeout *time.Duration `mapstructure:"timeout" yaml:"timeout,omitempty"`

	// IdleTimeout is distinct from UpstreamTimeout and defines period of time there may be no data over this connection
	// value of zero completely disables this setting
	// see https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/route/v3/route_components.proto#envoy-v3-api-field-config-route-v3-routeaction-idle-timeout
	IdleTimeout *time.Duration `mapstructure:"idle_timeout" yaml:"idle_timeout,omitempty"`

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
	TLSServerName           string `mapstructure:"tls_server_name" yaml:"tls_server_name,omitempty"`
	TLSDownstreamServerName string `mapstructure:"tls_downstream_server_name" yaml:"tls_downstream_server_name,omitempty"`
	TLSUpstreamServerName   string `mapstructure:"tls_upstream_server_name" yaml:"tls_upstream_server_name,omitempty"`

	// TLSCustomCA defines the  root certificate to use with a given
	// route when verifying server certificates.
	TLSCustomCA     string `mapstructure:"tls_custom_ca" yaml:"tls_custom_ca,omitempty"`
	TLSCustomCAFile string `mapstructure:"tls_custom_ca_file" yaml:"tls_custom_ca_file,omitempty"`

	// Contains the x.509 client certificate to present to the upstream host.
	TLSClientCert     string           `mapstructure:"tls_client_cert" yaml:"tls_client_cert,omitempty"`
	TLSClientKey      string           `mapstructure:"tls_client_key" yaml:"tls_client_key,omitempty"`
	TLSClientCertFile string           `mapstructure:"tls_client_cert_file" yaml:"tls_client_cert_file,omitempty"`
	TLSClientKeyFile  string           `mapstructure:"tls_client_key_file" yaml:"tls_client_key_file,omitempty"`
	ClientCertificate *tls.Certificate `yaml:",omitempty" hash:"-"`

	// TLSDownstreamClientCA defines the root certificate to use with a given route to verify
	// downstream client certificates (e.g. from a user's browser).
	TLSDownstreamClientCA     string `mapstructure:"tls_downstream_client_ca" yaml:"tls_downstream_client_ca,omitempty"`
	TLSDownstreamClientCAFile string `mapstructure:"tls_downstream_client_ca_file" yaml:"tls_downstream_client_ca_file,omitempty"`

	// TLSUpstreamAllowRenegotiation allows server-initiated TLS renegotiation.
	TLSUpstreamAllowRenegotiation bool `mapstructure:"tls_upstream_allow_renegotiation" yaml:"allow_renegotiation,omitempty"`

	// SetRequestHeaders adds a collection of headers to the upstream request
	// in the form of key value pairs. Note bene, this will overwrite the
	// value of any existing value of a given header key.
	SetRequestHeaders map[string]string `mapstructure:"set_request_headers" yaml:"set_request_headers,omitempty"`

	// RemoveRequestHeaders removes a collection of headers from an upstream request.
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

	// PassIdentityHeaders controls whether to add a user's identity headers to the upstream request.
	// These include:
	//
	//  - X-Pomerium-Jwt-Assertion
	//  - X-Pomerium-Claim-*
	//
	PassIdentityHeaders *bool `mapstructure:"pass_identity_headers" yaml:"pass_identity_headers,omitempty"`

	// KubernetesServiceAccountToken is the kubernetes token to use for upstream requests.
	KubernetesServiceAccountToken string `mapstructure:"kubernetes_service_account_token" yaml:"kubernetes_service_account_token,omitempty"`
	// KubernetesServiceAccountTokenFile contains the kubernetes token to use for upstream requests.
	KubernetesServiceAccountTokenFile string `mapstructure:"kubernetes_service_account_token_file" yaml:"kubernetes_service_account_token_file,omitempty"`

	// EnableGoogleCloudServerlessAuthentication adds "Authorization: Bearer ID_TOKEN" headers
	// to upstream requests.
	EnableGoogleCloudServerlessAuthentication bool `mapstructure:"enable_google_cloud_serverless_authentication" yaml:"enable_google_cloud_serverless_authentication,omitempty"`

	SubPolicies []SubPolicy `mapstructure:"sub_policies" yaml:"sub_policies,omitempty" json:"sub_policies,omitempty"`

	EnvoyOpts *envoy_config_cluster_v3.Cluster `mapstructure:"_envoy_opts" yaml:"-" json:"-"`

	// RewriteResponseHeaders rewrites response headers. This can be used to change the Location header.
	RewriteResponseHeaders []RewriteHeader `mapstructure:"rewrite_response_headers" yaml:"rewrite_response_headers,omitempty" json:"rewrite_response_headers,omitempty"`

	// SetResponseHeaders sets response headers.
	SetResponseHeaders map[string]string `mapstructure:"set_response_headers" yaml:"set_response_headers,omitempty"`

	// IDPClientID is the client id used for the identity provider.
	IDPClientID string `mapstructure:"idp_client_id" yaml:"idp_client_id,omitempty"`
	// IDPClientSecret is the client secret used for the identity provider.
	IDPClientSecret string `mapstructure:"idp_client_secret" yaml:"idp_client_secret,omitempty"`

	// ShowErrorDetails indicates whether or not additional error details should be displayed.
	ShowErrorDetails bool `mapstructure:"show_error_details" yaml:"show_error_details" json:"show_error_details"`

	Policy *PPLPolicy `mapstructure:"policy" yaml:"policy,omitempty" json:"policy,omitempty"`
}

// RewriteHeader is a policy configuration option to rewrite an HTTP header.
type RewriteHeader struct {
	Header string `mapstructure:"header" yaml:"header" json:"header"`
	Prefix string `mapstructure:"prefix" yaml:"prefix,omitempty" json:"prefix,omitempty"`
	Value  string `mapstructure:"value" yaml:"value,omitempty" json:"value,omitempty"`
}

// A SubPolicy is a protobuf Policy within a protobuf Route.
type SubPolicy struct {
	ID               string                   `mapstructure:"id" yaml:"id" json:"id"`
	Name             string                   `mapstructure:"name" yaml:"name" json:"name"`
	AllowedUsers     []string                 `mapstructure:"allowed_users" yaml:"allowed_users,omitempty" json:"allowed_users,omitempty"`
	AllowedDomains   []string                 `mapstructure:"allowed_domains" yaml:"allowed_domains,omitempty" json:"allowed_domains,omitempty"`
	AllowedIDPClaims identity.FlattenedClaims `mapstructure:"allowed_idp_claims" yaml:"allowed_idp_claims,omitempty" json:"allowed_idp_claims,omitempty"`
	Rego             []string                 `mapstructure:"rego" yaml:"rego" json:"rego,omitempty"`

	// Explanation is the explanation for why a policy failed.
	Explanation string `mapstructure:"explanation" yaml:"explanation" json:"explanation,omitempty"`
	// Remediation are the steps a user needs to take to gain access.
	Remediation string `mapstructure:"remediation" yaml:"remediation" json:"remediation,omitempty"`
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

// A DirectResponse is the response to an HTTP request.
type DirectResponse struct {
	Status int    `mapstructure:"status" yaml:"status,omitempty" json:"status,omitempty"`
	Body   string `mapstructure:"body" yaml:"body,omitempty" json:"body,omitempty"`
}

// NewPolicyFromProto creates a new Policy from a protobuf policy config route.
func NewPolicyFromProto(pb *configpb.Route) (*Policy, error) {
	var timeout *time.Duration
	if pb.GetTimeout() != nil {
		t := pb.GetTimeout().AsDuration()
		timeout = &t
	}
	var idleTimeout *time.Duration
	if pb.GetIdleTimeout() != nil {
		t := pb.GetIdleTimeout().AsDuration()
		idleTimeout = &t
	}

	p := &Policy{
		ID:                               pb.GetId(),
		From:                             pb.GetFrom(),
		AllowedUsers:                     pb.GetAllowedUsers(),
		AllowedDomains:                   pb.GetAllowedDomains(),
		AllowedIDPClaims:                 identity.NewFlattenedClaimsFromPB(pb.GetAllowedIdpClaims()),
		Prefix:                           pb.GetPrefix(),
		Path:                             pb.GetPath(),
		Regex:                            pb.GetRegex(),
		PrefixRewrite:                    pb.GetPrefixRewrite(),
		RegexRewritePattern:              pb.GetRegexRewritePattern(),
		RegexRewriteSubstitution:         pb.GetRegexRewriteSubstitution(),
		RegexPriorityOrder:               pb.RegexPriorityOrder,
		CORSAllowPreflight:               pb.GetCorsAllowPreflight(),
		AllowPublicUnauthenticatedAccess: pb.GetAllowPublicUnauthenticatedAccess(),
		AllowAnyAuthenticatedUser:        pb.GetAllowAnyAuthenticatedUser(),
		UpstreamTimeout:                  timeout,
		IdleTimeout:                      idleTimeout,
		AllowWebsockets:                  pb.GetAllowWebsockets(),
		AllowSPDY:                        pb.GetAllowSpdy(),
		TLSSkipVerify:                    pb.GetTlsSkipVerify(),
		TLSServerName:                    pb.GetTlsServerName(),
		TLSDownstreamServerName:          pb.GetTlsDownstreamServerName(),
		TLSUpstreamServerName:            pb.GetTlsUpstreamServerName(),
		TLSCustomCA:                      pb.GetTlsCustomCa(),
		TLSCustomCAFile:                  pb.GetTlsCustomCaFile(),
		TLSClientCert:                    pb.GetTlsClientCert(),
		TLSClientKey:                     pb.GetTlsClientKey(),
		TLSClientCertFile:                pb.GetTlsClientCertFile(),
		TLSClientKeyFile:                 pb.GetTlsClientKeyFile(),
		TLSDownstreamClientCA:            pb.GetTlsDownstreamClientCa(),
		TLSDownstreamClientCAFile:        pb.GetTlsDownstreamClientCaFile(),
		SetRequestHeaders:                pb.GetSetRequestHeaders(),
		RemoveRequestHeaders:             pb.GetRemoveRequestHeaders(),
		PreserveHostHeader:               pb.GetPreserveHostHeader(),
		HostRewrite:                      pb.GetHostRewrite(),
		HostRewriteHeader:                pb.GetHostRewriteHeader(),
		HostPathRegexRewritePattern:      pb.GetHostPathRegexRewritePattern(),
		HostPathRegexRewriteSubstitution: pb.GetHostPathRegexRewriteSubstitution(),
		PassIdentityHeaders:              pb.PassIdentityHeaders,
		KubernetesServiceAccountToken:    pb.GetKubernetesServiceAccountToken(),
		SetResponseHeaders:               pb.GetSetResponseHeaders(),
		EnableGoogleCloudServerlessAuthentication: pb.GetEnableGoogleCloudServerlessAuthentication(),
		IDPClientID:      pb.GetIdpClientId(),
		IDPClientSecret:  pb.GetIdpClientSecret(),
		ShowErrorDetails: pb.GetShowErrorDetails(),
	}
	if pb.Redirect.IsSet() {
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
	} else if pb.Response != nil {
		p.Response = &DirectResponse{
			Status: int(pb.Response.GetStatus()),
			Body:   pb.Response.GetBody(),
		}
	} else {
		to, err := ParseWeightedUrls(pb.GetTo()...)
		if err != nil {
			return nil, err
		}

		p.To = to
	}

	p.EnvoyOpts = pb.EnvoyOpts
	if p.EnvoyOpts == nil {
		p.EnvoyOpts = new(envoy_config_cluster_v3.Cluster)
	}
	if pb.Name != "" && p.EnvoyOpts.Name == "" {
		p.EnvoyOpts.Name = pb.Name
	}

	for _, rwh := range pb.RewriteResponseHeaders {
		p.RewriteResponseHeaders = append(p.RewriteResponseHeaders, RewriteHeader{
			Header: rwh.GetHeader(),
			Prefix: rwh.GetPrefix(),
			Value:  rwh.GetValue(),
		})
	}

	for _, sp := range pb.GetPolicies() {
		p.SubPolicies = append(p.SubPolicies, SubPolicy{
			ID:               sp.GetId(),
			Name:             sp.GetName(),
			AllowedUsers:     sp.GetAllowedUsers(),
			AllowedDomains:   sp.GetAllowedDomains(),
			AllowedIDPClaims: identity.NewFlattenedClaimsFromPB(sp.GetAllowedIdpClaims()),
			Rego:             sp.GetRego(),

			Explanation: sp.GetExplanation(),
			Remediation: sp.GetRemediation(),
		})
	}
	return p, p.Validate()
}

func (p *Policy) CopyToProto(dest *configpb.Route) error {
	routeId, err := p.RouteID()
	if err != nil {
		return err
	}

	dest.Name = strconv.FormatUint(routeId, 10)
	dest.From = p.From
	dest.AllowedUsers = p.AllowedUsers
	dest.AllowedDomains = p.AllowedDomains
	if p.AllowedIDPClaims != nil {
		dest.AllowedIdpClaims = p.AllowedIDPClaims.ToPB()
	}
	dest.Prefix = p.Prefix
	dest.Path = p.Path
	dest.Regex = p.Regex
	dest.PrefixRewrite = p.PrefixRewrite
	dest.RegexRewritePattern = p.RegexRewritePattern
	dest.RegexRewriteSubstitution = p.RegexRewriteSubstitution
	dest.CorsAllowPreflight = p.CORSAllowPreflight
	dest.AllowPublicUnauthenticatedAccess = p.AllowPublicUnauthenticatedAccess
	dest.AllowAnyAuthenticatedUser = p.AllowAnyAuthenticatedUser
	dest.AllowWebsockets = p.AllowWebsockets
	dest.AllowSpdy = p.AllowSPDY
	dest.TlsSkipVerify = p.TLSSkipVerify
	dest.TlsServerName = p.TLSServerName
	dest.TlsUpstreamServerName = p.TLSUpstreamServerName
	dest.TlsDownstreamServerName = p.TLSDownstreamServerName
	dest.TlsCustomCa = p.TLSCustomCA
	dest.TlsCustomCaFile = p.TLSCustomCAFile
	dest.TlsClientCert = p.TLSClientCert
	dest.TlsClientKey = p.TLSClientKey
	dest.TlsClientCertFile = p.TLSClientCertFile
	dest.TlsClientKeyFile = p.TLSClientKeyFile
	dest.TlsDownstreamClientCa = p.TLSDownstreamClientCA
	dest.TlsDownstreamClientCaFile = p.TLSDownstreamClientCAFile
	dest.SetRequestHeaders = p.SetRequestHeaders
	dest.RemoveRequestHeaders = p.RemoveRequestHeaders
	dest.PreserveHostHeader = p.PreserveHostHeader
	dest.PassIdentityHeaders = p.PassIdentityHeaders
	dest.KubernetesServiceAccountToken = p.KubernetesServiceAccountToken
	dest.SetResponseHeaders = p.SetResponseHeaders
	copySrcToOptionalDest(&dest.IdpClientId, &p.IDPClientID)
	copySrcToOptionalDest(&dest.IdpClientSecret, &p.IDPClientSecret)
	if p.Redirect != nil {
		if dest.Redirect == nil {
			dest.Redirect = &configpb.RouteRedirect{}
		}
		dest.Response = nil
		dest.To = nil
		dest.LoadBalancingWeights = nil

		copyOptionalSrcToOptionalDest(&dest.Redirect.HttpsRedirect, &p.Redirect.HTTPSRedirect)
		copyOptionalSrcToOptionalDest(&dest.Redirect.SchemeRedirect, &p.Redirect.SchemeRedirect)
		copyOptionalSrcToOptionalDest(&dest.Redirect.HostRedirect, &p.Redirect.HostRedirect)
		copyOptionalSrcToOptionalDest(&dest.Redirect.PortRedirect, &p.Redirect.PortRedirect)
		copyOptionalSrcToOptionalDest(&dest.Redirect.PathRedirect, &p.Redirect.PathRedirect)
		copyOptionalSrcToOptionalDest(&dest.Redirect.PrefixRewrite, &p.Redirect.PrefixRewrite)
		copyOptionalSrcToOptionalDest(&dest.Redirect.ResponseCode, &p.Redirect.ResponseCode)
		copyOptionalSrcToOptionalDest(&dest.Redirect.StripQuery, &p.Redirect.StripQuery)
	} else if p.Response != nil {
		if dest.Response == nil {
			dest.Response = &configpb.RouteDirectResponse{}
		}
		dest.Redirect = nil
		dest.To = nil
		dest.LoadBalancingWeights = nil

		dest.Response.Status = uint32(p.Response.Status)
		dest.Response.Body = p.Response.Body
	} else {
		clear(dest.To)
		dest.To = slices.Grow(dest.To[:0], len(p.To))
		clear(dest.LoadBalancingWeights)
		dest.LoadBalancingWeights = slices.Grow(dest.LoadBalancingWeights[:0], len(p.To))
		dest.Redirect = nil
		dest.Response = nil

		for _, u := range p.To {
			dest.To = append(dest.To, u.URL.String())
			dest.LoadBalancingWeights = append(dest.LoadBalancingWeights, u.LbWeight)
		}
	}
	copyOptionalDurationToOptionalDurationpb(&dest.Timeout, &p.UpstreamTimeout, &defaultOptions.DefaultUpstreamTimeout)
	copyOptionalDurationToOptionalDurationpb(&dest.IdleTimeout, &p.IdleTimeout, nil)

	clear(dest.Policies)
	dest.Policies = slices.Grow(dest.Policies[:0], len(p.SubPolicies))
	for _, sp := range p.SubPolicies {
		pb := &configpb.Policy{
			Id:             sp.ID,
			Name:           sp.Name,
			AllowedUsers:   sp.AllowedUsers,
			AllowedDomains: sp.AllowedDomains,
			Rego:           sp.Rego,
		}
		if sp.AllowedIDPClaims != nil {
			pb.AllowedIdpClaims = sp.AllowedIDPClaims.ToPB()
		}
		dest.Policies = append(dest.Policies, pb)
	}

	for _, rwh := range p.RewriteResponseHeaders {
		clear(dest.RewriteResponseHeaders)
		dest.RewriteResponseHeaders = append(dest.RewriteResponseHeaders[:0], &configpb.RouteRewriteHeader{
			Header: rwh.Header,
			Matcher: &configpb.RouteRewriteHeader_Prefix{
				Prefix: rwh.Prefix,
			},
			Value: rwh.Value,
		})
	}

	return nil
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

func copyOptionalSrcToOptionalDest[T comparable](dst, src **T) {
	if *dst == nil || *src == nil {
		*dst = *src
		return
	}
	**dst = **src
}

func copyOptionalDurationToOptionalDurationpb(dst **durationpb.Duration, src **time.Duration, def *time.Duration) {
	if *dst != nil {
		var nanos int64
		if *src == nil {
			if def == nil {
				*dst = nil
				return
			}
			nanos = int64(*def)
		} else {
			nanos = int64(**src)
		}
		seconds := nanos / int64(time.Second)
		(*dst).Seconds = seconds
		(*dst).Nanos = int32(nanos - seconds*int64(time.Second))
	} else {
		if *src == nil {
			if def != nil {
				*dst = durationpb.New(*def)
			}
		} else {
			*dst = durationpb.New(**src)
		}
	}
}

// ToProto converts the policy to a protobuf type.
func (p *Policy) ToProto() (*configpb.Route, error) {
	out := &configpb.Route{}
	if err := p.CopyToProto(out); err != nil {
		return nil, err
	}
	return out, nil
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
	if source.Scheme == "http" {
		log.Warn(context.Background()).Msgf("config: policy source url (%s) uses HTTP but only HTTPS is supported",
			source.String())
	}

	if len(p.To) == 0 && p.Redirect == nil && p.Response == nil {
		return errEitherToOrRedirectOrResponseRequired
	}

	toSchemes := make(map[string]struct{})
	for _, u := range p.To {
		if err = u.Validate(); err != nil {
			return fmt.Errorf("config: %s: %w", u.URL.String(), err)
		}
		toSchemes[u.URL.Scheme] = struct{}{}
	}

	// It is an error to mix TCP and non-TCP To URLs.
	if _, hasTCP := toSchemes["tcp"]; hasTCP && len(toSchemes) > 1 {
		return fmt.Errorf("config: cannot mix tcp and non-tcp To URLs")
	}

	// Only allow public access if no other whitelists are in place
	if p.AllowPublicUnauthenticatedAccess && (p.AllowAnyAuthenticatedUser || p.AllowedDomains != nil || p.AllowedUsers != nil) {
		return fmt.Errorf("config: policy route marked as public but contains whitelists")
	}

	// Only allow any authenticated user if no other whitelists are in place
	if p.AllowAnyAuthenticatedUser && (p.AllowedDomains != nil || p.AllowedUsers != nil) {
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

	const clientCADeprecationMsg = "config: %s is deprecated, see https://www.pomerium.com/docs/" +
		"reference/routes/tls#tls-downstream-client-certificate-authority for more information"

	if p.TLSDownstreamClientCA != "" {
		log.Warn(context.Background()).Msgf(clientCADeprecationMsg, "tls_downstream_client_ca")
		_, err := base64.StdEncoding.DecodeString(p.TLSDownstreamClientCA)
		if err != nil {
			return fmt.Errorf("config: couldn't decode downstream client ca: %w", err)
		}
	}

	if p.TLSDownstreamClientCAFile != "" {
		log.Warn(context.Background()).Msgf(clientCADeprecationMsg, "tls_downstream_client_ca_file")
		bs, err := os.ReadFile(p.TLSDownstreamClientCAFile)
		if err != nil {
			return fmt.Errorf("config: couldn't load downstream client ca: %w", err)
		}
		p.TLSDownstreamClientCA = base64.StdEncoding.EncodeToString(bs)
	}

	if p.KubernetesServiceAccountTokenFile != "" {
		if p.KubernetesServiceAccountToken != "" {
			return fmt.Errorf("config: specified both `kubernetes_service_account_token_file` and `kubernetes_service_account_token`")
		}

		token, err := os.ReadFile(p.KubernetesServiceAccountTokenFile)
		if err != nil {
			return fmt.Errorf("config: failed to load kubernetes service account token: %w", err)
		}
		p.KubernetesServiceAccountToken = string(token)
	}

	if p.PrefixRewrite != "" && p.RegexRewritePattern != "" {
		return fmt.Errorf("config: only prefix_rewrite or regex_rewrite_pattern can be specified, but not both")
	}

	if p.Regex != "" {
		rawRE := p.Regex
		if !strings.HasPrefix(rawRE, "^") {
			rawRE = "^" + rawRE
		}
		if !strings.HasSuffix(rawRE, "$") {
			rawRE += "$"
		}
		p.compiledRegex, _ = regexp.Compile(rawRE)
	}

	return nil
}

var policyPool = sync.Pool{
	New: func() any {
		return &configpb.Route{}
	},
}

var checksumBufferPool bytebufferpool.Pool

var marshalOpts = proto.MarshalOptions{
	Deterministic: true,
}

var (
	setRequestHeadersIv  = xxhash.Sum64String("Policy.SetRequestHeaders")
	setResponseHeadersIv = xxhash.Sum64String("Policy.SetResponseHeaders")
)

// Checksum returns the xxhash hash for the policy.
func (p *Policy) Checksum() uint64 {
	pb := policyPool.Get().(*configpb.Route)
	_ = p.CopyToProto(pb)
	var setReqHeaders, setRespHeaders map[string]string
	setReqHeaders, pb.SetRequestHeaders = pb.SetRequestHeaders, nil
	setRespHeaders, pb.SetResponseHeaders = pb.SetResponseHeaders, nil
	buf := checksumBufferPool.Get()
	buf.B, _ = marshalOpts.MarshalAppend(buf.B, pb)
	if setReqHeaders != nil {
		buf.B = binary.BigEndian.AppendUint64(buf.B, hashutil.MapHash(setRequestHeadersIv, setReqHeaders))
	}
	if setRespHeaders != nil {
		buf.B = binary.BigEndian.AppendUint64(buf.B, hashutil.MapHash(setResponseHeadersIv, setRespHeaders))
	}
	sum := xxhash.Sum64(buf.B)
	checksumBufferPool.Put(buf)
	policyPool.Put(pb)
	return sum
}

// RouteID returns a unique identifier for a route
func (p *Policy) RouteID() (uint64, error) {
	// this function is in the hot path, try not to allocate too much memory here
	hash := xxhash.New()
	hash.WriteString(p.From)
	hash.WriteString(p.Prefix)
	hash.WriteString(p.Path)
	hash.WriteString(p.Regex)
	if len(p.To) > 0 {
		for _, to := range p.To {
			hash.WriteString(to.URL.Scheme)
			hash.WriteString(to.URL.Opaque)
			if to.URL.User != nil {
				hash.WriteString(to.URL.User.Username())
				p, _ := to.URL.User.Password()
				hash.WriteString(p)
			}
			hash.WriteString(to.URL.Host)
			hash.WriteString(to.URL.Path)
			hash.WriteString(to.URL.RawPath)
			writeBool(hash, to.URL.OmitHost)
			writeBool(hash, to.URL.ForceQuery)
			hash.WriteString(to.URL.Fragment)
			hash.WriteString(to.URL.RawFragment)
			writeUint32(hash, to.LbWeight)
		}
	} else if p.Redirect != nil {
		if p.Redirect.HTTPSRedirect != nil {
			writeBool(hash, *p.Redirect.HTTPSRedirect)
		}
		if p.Redirect.SchemeRedirect != nil {
			hash.WriteString(*p.Redirect.SchemeRedirect)
		}
		if p.Redirect.HostRedirect != nil {
			hash.WriteString(*p.Redirect.HostRedirect)
		}
		if p.Redirect.PortRedirect != nil {
			writeUint32(hash, *p.Redirect.PortRedirect)
		}
		if p.Redirect.PathRedirect != nil {
			hash.WriteString(*p.Redirect.PathRedirect)
		}
		if p.Redirect.PrefixRewrite != nil {
			hash.WriteString(*p.Redirect.PrefixRewrite)
		}
		if p.Redirect.ResponseCode != nil {
			writeInt32(hash, *p.Redirect.ResponseCode)
		}
		if p.Redirect.StripQuery != nil {
			writeBool(hash, *p.Redirect.StripQuery)
		}
	} else if p.Response != nil {
		writeUint32(hash, uint32(p.Response.Status)) // this seems to be converted from uint32 anyway
		hash.WriteString(p.Response.Body)
	} else {
		return 0, errEitherToOrRedirectOrResponseRequired
	}
	return hash.Sum64(), nil
}

func writeBool(hash *xxhash.Digest, b bool) {
	if b {
		hash.Write([]byte{1})
	} else {
		hash.Write([]byte{0})
	}
}

func writeUint32(hash *xxhash.Digest, t uint32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], t)
	hash.Write(buf[:])
}

func writeInt32(hash *xxhash.Digest, t int32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], *(*uint32)(unsafe.Pointer(&t)))
	hash.Write(buf[:])
}

func (p *Policy) String() string {
	to := "?"
	if len(p.To) > 0 {
		var dsts []string
		for _, dst := range p.To {
			dsts = append(dsts, dst.URL.String())
		}
		to = strings.Join(dsts, ",")
	}

	return fmt.Sprintf("%s → %s", p.From, to)
}

// Matches returns true if the policy would match the given URL.
func (p *Policy) Matches(requestURL url.URL, stripPort bool) bool {
	// an invalid from URL should not match anything
	fromURL, err := urlutil.ParseAndValidateURL(p.From)
	if err != nil {
		return false
	}

	if !FromURLMatchesRequestURL(fromURL, &requestURL, stripPort) {
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

	if p.compiledRegex != nil {
		if !p.compiledRegex.MatchString(requestURL.Path) {
			return false
		}
	}

	return true
}

// IsForKubernetes returns true if the policy is for kubernetes.
func (p *Policy) IsForKubernetes() bool {
	return p.KubernetesServiceAccountTokenFile != "" || p.KubernetesServiceAccountToken != ""
}

// IsTCP returns true if the route is for TCP.
func (p *Policy) IsTCP() bool {
	return strings.HasPrefix(p.From, "tcp")
}

// IsTCPUpstream returns true if the route has a TCP upstream (To) URL
func (p *Policy) IsTCPUpstream() bool {
	return len(p.To) > 0 && p.To[0].URL.Scheme == "tcp"
}

// AllAllowedDomains returns all the allowed domains.
func (p *Policy) AllAllowedDomains() []string {
	var ads []string
	ads = append(ads, p.AllowedDomains...)
	for _, sp := range p.SubPolicies {
		ads = append(ads, sp.AllowedDomains...)
	}
	return ads
}

// AllAllowedIDPClaims returns all the allowed IDP claims.
func (p *Policy) AllAllowedIDPClaims() []identity.FlattenedClaims {
	var aics []identity.FlattenedClaims
	if len(p.AllowedIDPClaims) > 0 {
		aics = append(aics, p.AllowedIDPClaims)
	}
	for _, sp := range p.SubPolicies {
		if len(sp.AllowedIDPClaims) > 0 {
			aics = append(aics, sp.AllowedIDPClaims)
		}
	}
	return aics
}

// AllAllowedUsers returns all the allowed users.
func (p *Policy) AllAllowedUsers() []string {
	var aus []string
	aus = append(aus, p.AllowedUsers...)
	for _, sp := range p.SubPolicies {
		aus = append(aus, sp.AllowedUsers...)
	}
	return aus
}

// GetPassIdentityHeaders gets the pass identity headers option. If not set in the policy, use the setting from the
// options. If not set in either, return false.
func (p *Policy) GetPassIdentityHeaders(options *Options) bool {
	if p != nil && p.PassIdentityHeaders != nil {
		return *p.PassIdentityHeaders
	}

	if options != nil && options.PassIdentityHeaders != nil {
		return *options.PassIdentityHeaders
	}

	return false
}

/*
SortPolicies sorts policies to match the following SQL order:

	  ORDER BY from ASC,
		path DESC NULLS LAST,
		regex_priority_order DESC NULLS LAST,
		regex DESC NULLS LAST
		prefix DESC NULLS LAST,
		id ASC
*/
func SortPolicies(pp []Policy) {
	sort.SliceStable(pp, func(i, j int) bool {
		strDesc := func(a, b string) (val bool, equal bool) {
			return a > b, a == b
		}

		strAsc := func(a, b string) (val bool, equal bool) {
			return a < b, a == b
		}

		intPDesc := func(a, b *int64) (val bool, equal bool) {
			if a == nil && b == nil {
				return false, true
			}
			if a == nil && b != nil {
				return false, false
			}
			if a != nil && b == nil {
				return true, false
			}
			return *a > *b, *a == *b
		}

		if val, equal := strAsc(pp[i].From, pp[j].From); !equal {
			return val
		}

		if val, equal := strDesc(pp[i].Path, pp[j].Path); !equal {
			return val
		}

		if val, equal := intPDesc(pp[i].RegexPriorityOrder, pp[j].RegexPriorityOrder); !equal {
			return val
		}

		if val, equal := strDesc(pp[i].Regex, pp[j].Regex); !equal {
			return val
		}

		if val, equal := strDesc(pp[i].Prefix, pp[j].Prefix); !equal {
			return val
		}

		return pp[i].ID < pp[j].ID // Ascending order for ID
	})
}
