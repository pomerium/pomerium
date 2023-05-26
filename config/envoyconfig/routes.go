package envoyconfig

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

const (
	httpCluster = "pomerium-control-plane-http"
)

func (b *Builder) buildGRPCRoutes() ([]*envoy_config_route_v3.Route, error) {
	action := &envoy_config_route_v3.Route_Route{
		Route: &envoy_config_route_v3.RouteAction{
			ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
				Cluster: "pomerium-control-plane-grpc",
			},
		},
	}
	return []*envoy_config_route_v3.Route{{
		Name: "pomerium-grpc",
		Match: &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
				Prefix: "/",
			},
			Grpc: &envoy_config_route_v3.RouteMatch_GrpcRouteMatchOptions{},
		},
		Action: action,
		TypedPerFilterConfig: map[string]*any.Any{
			PerFilterConfigExtAuthzName: PerFilterConfigExtAuthzDisabled(),
		},
	}}, nil
}

func (b *Builder) buildPomeriumHTTPRoutes(
	options *config.Options,
	host string,
	requireStrictTransportSecurity bool,
) ([]*envoy_config_route_v3.Route, error) {
	var routes []*envoy_config_route_v3.Route

	// if this is the pomerium proxy in front of the the authenticate service, don't add
	// these routes since they will be handled by authenticate
	isFrontingAuthenticate, err := isProxyFrontingAuthenticate(options, host)
	if err != nil {
		return nil, err
	}
	if !isFrontingAuthenticate {
		routes = append(routes,
			b.buildControlPlanePathRoute(options, "/ping", requireStrictTransportSecurity),
			b.buildControlPlanePathRoute(options, "/healthz", requireStrictTransportSecurity),
			b.buildControlPlanePathRoute(options, "/.pomerium", requireStrictTransportSecurity),
			b.buildControlPlanePrefixRoute(options, "/.pomerium/", requireStrictTransportSecurity),
			b.buildControlPlanePathRoute(options, "/.well-known/pomerium", requireStrictTransportSecurity),
			b.buildControlPlanePrefixRoute(options, "/.well-known/pomerium/", requireStrictTransportSecurity),
		)
		// per #837, only add robots.txt if there are no unauthenticated routes
		if !hasPublicPolicyMatchingURL(options, url.URL{Scheme: "https", Host: host, Path: "/robots.txt"}) {
			routes = append(routes, b.buildControlPlanePathRoute(options, "/robots.txt", requireStrictTransportSecurity))
		}
	}

	authRoutes, err := b.buildPomeriumAuthenticateHTTPRoutes(options, host, requireStrictTransportSecurity)
	if err != nil {
		return nil, err
	}
	routes = append(routes, authRoutes...)
	return routes, nil
}

func (b *Builder) buildPomeriumAuthenticateHTTPRoutes(
	options *config.Options,
	host string,
	requireStrictTransportSecurity bool,
) ([]*envoy_config_route_v3.Route, error) {
	if !config.IsAuthenticate(options.Services) {
		return nil, nil
	}

	for _, fn := range []func() (*url.URL, error){
		options.GetAuthenticateURL,
		options.GetInternalAuthenticateURL,
	} {
		u, err := fn()
		if err != nil {
			return nil, err
		}
		if urlMatchesHost(u, host) {
			return []*envoy_config_route_v3.Route{
				b.buildControlPlanePathRoute(options, options.AuthenticateCallbackPath, requireStrictTransportSecurity),
				b.buildControlPlanePathRoute(options, "/", requireStrictTransportSecurity),
			}, nil
		}
	}
	return nil, nil
}

func (b *Builder) buildControlPlanePathRoute(
	options *config.Options,
	path string,
	requireStrictTransportSecurity bool,
) *envoy_config_route_v3.Route {
	r := &envoy_config_route_v3.Route{
		Name: "pomerium-path-" + path,
		Match: &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{Path: path},
		},
		Action: &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{
				ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
					Cluster: httpCluster,
				},
			},
		},
		ResponseHeadersToAdd: toEnvoyHeaders(options.GetSetResponseHeaders(requireStrictTransportSecurity)),
		TypedPerFilterConfig: map[string]*any.Any{
			PerFilterConfigExtAuthzName: PerFilterConfigExtAuthzContextExtensions(MakeExtAuthzContextExtensions(true, 0)),
		},
	}
	return r
}

func (b *Builder) buildControlPlanePrefixRoute(
	options *config.Options,
	prefix string,
	requireStrictTransportSecurity bool,
) *envoy_config_route_v3.Route {
	r := &envoy_config_route_v3.Route{
		Name: "pomerium-prefix-" + prefix,
		Match: &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{Prefix: prefix},
		},
		Action: &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{
				ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
					Cluster: httpCluster,
				},
			},
		},
		ResponseHeadersToAdd: toEnvoyHeaders(options.GetSetResponseHeaders(requireStrictTransportSecurity)),
		TypedPerFilterConfig: map[string]*any.Any{
			PerFilterConfigExtAuthzName: PerFilterConfigExtAuthzContextExtensions(MakeExtAuthzContextExtensions(true, 0)),
		},
	}
	return r
}

// getClusterID returns a cluster ID
var getClusterID = func(policy *config.Policy) string {
	prefix := getClusterStatsName(policy)
	if prefix == "" {
		prefix = "route"
	}

	id, _ := policy.RouteID()
	return fmt.Sprintf("%s-%x", prefix, id)
}

// getClusterStatsName returns human readable name that would be used by envoy to emit statistics, available as envoy_cluster_name label
func getClusterStatsName(policy *config.Policy) string {
	if policy.EnvoyOpts != nil && policy.EnvoyOpts.Name != "" {
		return policy.EnvoyOpts.Name
	}
	return ""
}

func (b *Builder) buildRoutesForPoliciesWithHost(
	cfg *config.Config,
	certs []tls.Certificate,
	host string,
) ([]*envoy_config_route_v3.Route, error) {
	var routes []*envoy_config_route_v3.Route
	for i, p := range cfg.Options.GetAllPolicies() {
		policy := p
		fromURL, err := urlutil.ParseAndValidateURL(policy.From)
		if err != nil {
			return nil, err
		}

		if !urlMatchesHost(fromURL, host) {
			continue
		}

		policyRoutes, err := b.buildRoutesForPolicy(cfg, certs, &policy, fmt.Sprintf("policy-%d", i))
		if err != nil {
			return nil, err
		}

		routes = append(routes, policyRoutes...)
	}
	return routes, nil
}

func (b *Builder) buildRoutesForPoliciesWithCatchAll(
	cfg *config.Config,
	certs []tls.Certificate,
) ([]*envoy_config_route_v3.Route, error) {
	var routes []*envoy_config_route_v3.Route
	for i, p := range cfg.Options.GetAllPolicies() {
		policy := p
		fromURL, err := urlutil.ParseAndValidateURL(policy.From)
		if err != nil {
			return nil, err
		}

		if !strings.Contains(fromURL.Host, "*") {
			continue
		}

		policyRoutes, err := b.buildRoutesForPolicy(cfg, certs, &policy, fmt.Sprintf("policy-%d", i))
		if err != nil {
			return nil, err
		}

		routes = append(routes, policyRoutes...)
	}
	return routes, nil
}

func (b *Builder) buildRoutesForPolicy(
	cfg *config.Config,
	certs []tls.Certificate,
	policy *config.Policy,
	name string,
) ([]*envoy_config_route_v3.Route, error) {
	fromURL, err := urlutil.ParseAndValidateURL(policy.From)
	if err != nil {
		return nil, err
	}

	var routes []*envoy_config_route_v3.Route
	if strings.Contains(fromURL.Host, "*") {
		// we have to match '*.example.com' and '*.example.com:443', so there are two routes
		for _, host := range urlutil.GetDomainsForURL(fromURL) {
			route, err := b.buildRouteForPolicyAndMatch(cfg, certs, policy, name, mkRouteMatchForHost(policy, host))
			if err != nil {
				return nil, err
			}
			routes = append(routes, route)
		}
	} else {
		route, err := b.buildRouteForPolicyAndMatch(cfg, certs, policy, name, mkRouteMatch(policy))
		if err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	return routes, nil
}

func (b *Builder) buildRouteForPolicyAndMatch(
	cfg *config.Config,
	certs []tls.Certificate,
	policy *config.Policy,
	name string,
	match *envoy_config_route_v3.RouteMatch,
) (*envoy_config_route_v3.Route, error) {
	fromURL, err := urlutil.ParseAndValidateURL(policy.From)
	if err != nil {
		return nil, err
	}

	routeID, err := policy.RouteID()
	if err != nil {
		return nil, err
	}

	requireStrictTransportSecurity := cryptutil.HasCertificateForServerName(certs, fromURL.Hostname())

	route := &envoy_config_route_v3.Route{
		Name:                   name,
		Match:                  match,
		Metadata:               &envoy_config_core_v3.Metadata{},
		RequestHeadersToAdd:    toEnvoyHeaders(policy.SetRequestHeaders),
		RequestHeadersToRemove: getRequestHeadersToRemove(cfg.Options, policy),
		ResponseHeadersToAdd:   toEnvoyHeaders(cfg.Options.GetSetResponseHeadersForPolicy(policy, requireStrictTransportSecurity)),
	}
	if policy.Redirect != nil {
		action, err := b.buildPolicyRouteRedirectAction(policy.Redirect)
		if err != nil {
			return nil, err
		}
		route.Action = &envoy_config_route_v3.Route_Redirect{Redirect: action}
	} else {
		action, err := b.buildPolicyRouteRouteAction(cfg.Options, policy)
		if err != nil {
			return nil, err
		}
		route.Action = &envoy_config_route_v3.Route_Route{Route: action}
	}

	luaMetadata := map[string]*structpb.Value{
		"rewrite_response_headers": getRewriteHeadersMetadata(policy.RewriteResponseHeaders),
	}

	// disable authentication entirely when the proxy is fronting authenticate
	isFrontingAuthenticate, err := isProxyFrontingAuthenticate(cfg.Options, fromURL.Hostname())
	if err != nil {
		return nil, err
	}
	if isFrontingAuthenticate {
		route.TypedPerFilterConfig = map[string]*any.Any{
			PerFilterConfigExtAuthzName: PerFilterConfigExtAuthzDisabled(),
		}
	} else {
		route.TypedPerFilterConfig = map[string]*any.Any{
			PerFilterConfigExtAuthzName: PerFilterConfigExtAuthzContextExtensions(MakeExtAuthzContextExtensions(false, routeID)),
		}
		luaMetadata["remove_pomerium_cookie"] = &structpb.Value{
			Kind: &structpb.Value_StringValue{
				StringValue: cfg.Options.CookieName,
			},
		}
		luaMetadata["remove_pomerium_authorization"] = &structpb.Value{
			Kind: &structpb.Value_BoolValue{
				BoolValue: true,
			},
		}
		luaMetadata["remove_impersonate_headers"] = &structpb.Value{
			Kind: &structpb.Value_BoolValue{
				BoolValue: policy.IsForKubernetes(),
			},
		}
	}

	if policy.IsForKubernetes() {
		for _, hdr := range b.reproxy.GetPolicyIDHeaders(routeID) {
			route.RequestHeadersToAdd = append(route.RequestHeadersToAdd,
				&envoy_config_core_v3.HeaderValueOption{
					Header: &envoy_config_core_v3.HeaderValue{
						Key:   hdr[0],
						Value: hdr[1],
					},
					AppendAction: envoy_config_core_v3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
				})
		}
	}

	route.Metadata.FilterMetadata = map[string]*structpb.Struct{
		"envoy.filters.http.lua": {Fields: luaMetadata},
	}
	return route, nil
}

func (b *Builder) buildPolicyRouteRedirectAction(r *config.PolicyRedirect) (*envoy_config_route_v3.RedirectAction, error) {
	action := &envoy_config_route_v3.RedirectAction{}
	switch {
	case r.HTTPSRedirect != nil:
		action.SchemeRewriteSpecifier = &envoy_config_route_v3.RedirectAction_HttpsRedirect{
			HttpsRedirect: *r.HTTPSRedirect,
		}
	case r.SchemeRedirect != nil:
		action.SchemeRewriteSpecifier = &envoy_config_route_v3.RedirectAction_SchemeRedirect{
			SchemeRedirect: *r.SchemeRedirect,
		}
	}
	if r.HostRedirect != nil {
		action.HostRedirect = *r.HostRedirect
	}
	if r.PortRedirect != nil {
		action.PortRedirect = *r.PortRedirect
	}
	switch {
	case r.PathRedirect != nil:
		action.PathRewriteSpecifier = &envoy_config_route_v3.RedirectAction_PathRedirect{
			PathRedirect: *r.PathRedirect,
		}
	case r.PrefixRewrite != nil:
		action.PathRewriteSpecifier = &envoy_config_route_v3.RedirectAction_PrefixRewrite{
			PrefixRewrite: *r.PrefixRewrite,
		}
	}
	if r.ResponseCode != nil {
		action.ResponseCode = envoy_config_route_v3.RedirectAction_RedirectResponseCode(*r.ResponseCode)
	}
	if r.StripQuery != nil {
		action.StripQuery = *r.StripQuery
	}
	return action, nil
}

func (b *Builder) buildPolicyRouteRouteAction(options *config.Options, policy *config.Policy) (*envoy_config_route_v3.RouteAction, error) {
	clusterName := getClusterID(policy)
	// kubernetes requests are sent to the http control plane to be reproxied
	if policy.IsForKubernetes() {
		clusterName = httpCluster
	}
	routeTimeout := getRouteTimeout(options, policy)
	idleTimeout := getRouteIdleTimeout(policy)
	prefixRewrite, regexRewrite := getRewriteOptions(policy)
	upgradeConfigs := []*envoy_config_route_v3.RouteAction_UpgradeConfig{
		{
			UpgradeType: "websocket",
			Enabled:     &wrappers.BoolValue{Value: policy.AllowWebsockets},
		},
		{
			UpgradeType: "spdy/3.1",
			Enabled:     &wrappers.BoolValue{Value: policy.AllowSPDY},
		},
	}

	if policy.IsTCP() {
		upgradeConfigs = append(upgradeConfigs, &envoy_config_route_v3.RouteAction_UpgradeConfig{
			UpgradeType:   "CONNECT",
			Enabled:       &wrappers.BoolValue{Value: true},
			ConnectConfig: &envoy_config_route_v3.RouteAction_UpgradeConfig_ConnectConfig{},
		})
	}
	action := &envoy_config_route_v3.RouteAction{
		ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
			Cluster: clusterName,
		},
		UpgradeConfigs: upgradeConfigs,
		HostRewriteSpecifier: &envoy_config_route_v3.RouteAction_AutoHostRewrite{
			AutoHostRewrite: &wrappers.BoolValue{Value: !policy.PreserveHostHeader},
		},
		Timeout:       routeTimeout,
		IdleTimeout:   idleTimeout,
		PrefixRewrite: prefixRewrite,
		RegexRewrite:  regexRewrite,
		HashPolicy: []*envoy_config_route_v3.RouteAction_HashPolicy{
			// hash by the routing key, which is added by authorize.
			{
				PolicySpecifier: &envoy_config_route_v3.RouteAction_HashPolicy_Header_{
					Header: &envoy_config_route_v3.RouteAction_HashPolicy_Header{
						HeaderName: httputil.HeaderPomeriumRoutingKey,
					},
				},
				Terminal: true,
			},
			// if the routing key is missing, hash by the ip.
			{
				PolicySpecifier: &envoy_config_route_v3.RouteAction_HashPolicy_ConnectionProperties_{
					ConnectionProperties: &envoy_config_route_v3.RouteAction_HashPolicy_ConnectionProperties{
						SourceIp: true,
					},
				},
				Terminal: true,
			},
		},
	}
	setHostRewriteOptions(policy, action)

	return action, nil
}

func mkEnvoyHeader(k, v string) *envoy_config_core_v3.HeaderValueOption {
	return &envoy_config_core_v3.HeaderValueOption{
		Header: &envoy_config_core_v3.HeaderValue{
			Key:   k,
			Value: v,
		},
		AppendAction: envoy_config_core_v3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	}
}

func toEnvoyHeaders(headers map[string]string) []*envoy_config_core_v3.HeaderValueOption {
	var ks []string
	for k := range headers {
		ks = append(ks, k)
	}
	sort.Strings(ks)

	envoyHeaders := make([]*envoy_config_core_v3.HeaderValueOption, 0, len(headers))
	for _, k := range ks {
		envoyHeaders = append(envoyHeaders, mkEnvoyHeader(k, headers[k]))
	}
	return envoyHeaders
}

func mkRouteMatch(policy *config.Policy) *envoy_config_route_v3.RouteMatch {
	match := &envoy_config_route_v3.RouteMatch{}
	switch {
	case policy.IsTCP():
		match.PathSpecifier = &envoy_config_route_v3.RouteMatch_ConnectMatcher_{
			ConnectMatcher: &envoy_config_route_v3.RouteMatch_ConnectMatcher{},
		}
	case policy.Regex != "":
		match.PathSpecifier = &envoy_config_route_v3.RouteMatch_SafeRegex{
			SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
				Regex: policy.Regex,
			},
		}
	case policy.Path != "":
		match.PathSpecifier = &envoy_config_route_v3.RouteMatch_Path{Path: policy.Path}
	case policy.Prefix != "":
		match.PathSpecifier = &envoy_config_route_v3.RouteMatch_Prefix{Prefix: policy.Prefix}
	default:
		match.PathSpecifier = &envoy_config_route_v3.RouteMatch_Prefix{Prefix: "/"}
	}
	return match
}

func mkRouteMatchForHost(
	policy *config.Policy,
	host string,
) *envoy_config_route_v3.RouteMatch {
	match := mkRouteMatch(policy)
	match.Headers = append(match.Headers, &envoy_config_route_v3.HeaderMatcher{
		Name: ":authority",
		HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{
			StringMatch: &envoy_type_matcher_v3.StringMatcher{
				MatchPattern: &envoy_type_matcher_v3.StringMatcher_SafeRegex{
					SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
						Regex: config.WildcardToRegex(host),
					},
				},
			},
		},
	})
	return match
}

func getRequestHeadersToRemove(options *config.Options, policy *config.Policy) []string {
	requestHeadersToRemove := policy.RemoveRequestHeaders
	if !policy.PassIdentityHeaders {
		requestHeadersToRemove = append(requestHeadersToRemove,
			httputil.HeaderPomeriumJWTAssertion,
			httputil.HeaderPomeriumJWTAssertionFor)
		for headerName := range options.JWTClaimsHeaders {
			requestHeadersToRemove = append(requestHeadersToRemove, headerName)
		}
	}
	// remove these headers to prevent a user from re-proxying requests through the control plane
	requestHeadersToRemove = append(requestHeadersToRemove,
		httputil.HeaderPomeriumReproxyPolicy,
		httputil.HeaderPomeriumReproxyPolicyHMAC,
	)
	return requestHeadersToRemove
}

func getRouteTimeout(options *config.Options, policy *config.Policy) *durationpb.Duration {
	var routeTimeout *durationpb.Duration
	if policy.UpstreamTimeout != nil {
		routeTimeout = durationpb.New(*policy.UpstreamTimeout)
	} else if shouldDisableStreamIdleTimeout(policy) {
		// a non-zero value would conflict with idleTimeout and/or websocket / tcp calls
		routeTimeout = durationpb.New(0)
	} else {
		routeTimeout = durationpb.New(options.DefaultUpstreamTimeout)
	}
	return routeTimeout
}

func getRouteIdleTimeout(policy *config.Policy) *durationpb.Duration {
	var idleTimeout *durationpb.Duration
	if policy.IdleTimeout != nil {
		idleTimeout = durationpb.New(*policy.IdleTimeout)
	} else if shouldDisableStreamIdleTimeout(policy) {
		idleTimeout = durationpb.New(0)
	}
	return idleTimeout
}

func shouldDisableStreamIdleTimeout(policy *config.Policy) bool {
	return policy.AllowWebsockets ||
		policy.IsTCP() ||
		policy.IsForKubernetes() // disable for kubernetes so that tailing logs works (#2182)
}

func getRewriteOptions(policy *config.Policy) (prefixRewrite string, regexRewrite *envoy_type_matcher_v3.RegexMatchAndSubstitute) {
	if policy.PrefixRewrite != "" {
		prefixRewrite = policy.PrefixRewrite
	} else if policy.RegexRewritePattern != "" {
		regexRewrite = &envoy_type_matcher_v3.RegexMatchAndSubstitute{
			Pattern: &envoy_type_matcher_v3.RegexMatcher{
				Regex: policy.RegexRewritePattern,
			},
			Substitution: policy.RegexRewriteSubstitution,
		}
	} else if len(policy.To) > 0 && policy.To[0].URL.Path != "" {
		prefixRewrite = policy.To[0].URL.Path
	}

	return prefixRewrite, regexRewrite
}

func setHostRewriteOptions(policy *config.Policy, action *envoy_config_route_v3.RouteAction) {
	switch {
	case policy.HostRewrite != "":
		action.HostRewriteSpecifier = &envoy_config_route_v3.RouteAction_HostRewriteLiteral{
			HostRewriteLiteral: policy.HostRewrite,
		}
	case policy.HostRewriteHeader != "":
		action.HostRewriteSpecifier = &envoy_config_route_v3.RouteAction_HostRewriteHeader{
			HostRewriteHeader: policy.HostRewriteHeader,
		}
	case policy.HostPathRegexRewritePattern != "":
		action.HostRewriteSpecifier = &envoy_config_route_v3.RouteAction_HostRewritePathRegex{
			HostRewritePathRegex: &envoy_type_matcher_v3.RegexMatchAndSubstitute{
				Pattern: &envoy_type_matcher_v3.RegexMatcher{
					Regex: policy.HostPathRegexRewritePattern,
				},
				Substitution: policy.HostPathRegexRewriteSubstitution,
			},
		}
	case policy.PreserveHostHeader:
		action.HostRewriteSpecifier = &envoy_config_route_v3.RouteAction_AutoHostRewrite{
			AutoHostRewrite: wrapperspb.Bool(false),
		}
	default:
		action.HostRewriteSpecifier = &envoy_config_route_v3.RouteAction_AutoHostRewrite{
			AutoHostRewrite: wrapperspb.Bool(true),
		}
	}
}

func hasPublicPolicyMatchingURL(options *config.Options, requestURL url.URL) bool {
	for _, policy := range options.GetAllPolicies() {
		if policy.AllowPublicUnauthenticatedAccess && policy.Matches(requestURL) {
			return true
		}
	}
	return false
}

func isProxyFrontingAuthenticate(options *config.Options, host string) (bool, error) {
	authenticateURL, err := options.GetAuthenticateURL()
	if err != nil {
		return false, err
	}

	if !config.IsAuthenticate(options.Services) && urlMatchesHost(authenticateURL, host) {
		return true, nil
	}

	return false, nil
}

func getRewriteHeadersMetadata(headers []config.RewriteHeader) *structpb.Value {
	if len(headers) == 0 {
		return &structpb.Value{
			Kind: &structpb.Value_ListValue{
				ListValue: new(structpb.ListValue),
			},
		}
	}
	var obj interface{}
	bs, _ := json.Marshal(headers)
	_ = json.Unmarshal(bs, &obj)
	v, _ := structpb.NewValue(obj)
	return v
}
