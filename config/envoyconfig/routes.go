package envoyconfig

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"

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
			"envoy.filters.http.ext_authz": disableExtAuthz,
		},
	}}, nil
}

func (b *Builder) buildPomeriumHTTPRoutes(options *config.Options, host string) ([]*envoy_config_route_v3.Route, error) {
	var routes []*envoy_config_route_v3.Route

	// if this is the pomerium proxy in front of the the authenticate service, don't add
	// these routes since they will be handled by authenticate
	isFrontingAuthenticate, err := isProxyFrontingAuthenticate(options, host)
	if err != nil {
		return nil, err
	}
	if !isFrontingAuthenticate {
		routes = append(routes,
			// enable ext_authz
			b.buildControlPlanePathRoute("/.pomerium/jwt", true),
			b.buildControlPlanePathRoute(urlutil.WebAuthnURLPath, true),
			// disable ext_authz and passthrough to proxy handlers
			b.buildControlPlanePathRoute("/ping", false),
			b.buildControlPlanePathRoute("/healthz", false),
			b.buildControlPlanePathRoute("/.pomerium", false),
			b.buildControlPlanePrefixRoute("/.pomerium/", false),
			b.buildControlPlanePathRoute("/.well-known/pomerium", false),
			b.buildControlPlanePrefixRoute("/.well-known/pomerium/", false),
		)
		// per #837, only add robots.txt if there are no unauthenticated routes
		if !hasPublicPolicyMatchingURL(options, url.URL{Scheme: "https", Host: host, Path: "/robots.txt"}) {
			routes = append(routes, b.buildControlPlanePathRoute("/robots.txt", false))
		}
	}

	authRoutes, err := b.buildPomeriumAuthenticateHTTPRoutes(options, host)
	if err != nil {
		return nil, err
	}
	routes = append(routes, authRoutes...)
	return routes, nil
}

func (b *Builder) buildPomeriumAuthenticateHTTPRoutes(options *config.Options, host string) ([]*envoy_config_route_v3.Route, error) {
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
				b.buildControlPlanePathRoute(options.AuthenticateCallbackPath, false),
				b.buildControlPlanePathRoute("/", false),
			}, nil
		}
	}
	return nil, nil
}

func (b *Builder) buildControlPlanePathRoute(path string, protected bool) *envoy_config_route_v3.Route {
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
	}
	if !protected {
		r.TypedPerFilterConfig = map[string]*any.Any{
			"envoy.filters.http.ext_authz": disableExtAuthz,
		}
	}
	return r
}

func (b *Builder) buildControlPlanePrefixRoute(prefix string, protected bool) *envoy_config_route_v3.Route {
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
	}
	if !protected {
		r.TypedPerFilterConfig = map[string]*any.Any{
			"envoy.filters.http.ext_authz": disableExtAuthz,
		}
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

func (b *Builder) buildPolicyRoutes(options *config.Options, host string) ([]*envoy_config_route_v3.Route, error) {
	var routes []*envoy_config_route_v3.Route

	for i, p := range options.GetAllPolicies() {
		policy := p
		if !urlMatchesHost(policy.Source.URL, host) {
			continue
		}

		match := mkRouteMatch(&policy)
		envoyRoute := &envoy_config_route_v3.Route{
			Name:                   fmt.Sprintf("policy-%d", i),
			Match:                  match,
			Metadata:               &envoy_config_core_v3.Metadata{},
			RequestHeadersToAdd:    toEnvoyHeaders(policy.SetRequestHeaders),
			RequestHeadersToRemove: getRequestHeadersToRemove(options, &policy),
			ResponseHeadersToAdd:   toEnvoyHeaders(policy.SetResponseHeaders),
		}
		if policy.Redirect != nil {
			action, err := b.buildPolicyRouteRedirectAction(policy.Redirect)
			if err != nil {
				return nil, err
			}
			envoyRoute.Action = &envoy_config_route_v3.Route_Redirect{Redirect: action}
		} else {
			action, err := b.buildPolicyRouteRouteAction(options, &policy)
			if err != nil {
				return nil, err
			}
			envoyRoute.Action = &envoy_config_route_v3.Route_Route{Route: action}
		}

		luaMetadata := map[string]*structpb.Value{
			"rewrite_response_headers": getRewriteHeadersMetadata(policy.RewriteResponseHeaders),
		}

		// disable authentication entirely when the proxy is fronting authenticate
		isFrontingAuthenticate, err := isProxyFrontingAuthenticate(options, host)
		if err != nil {
			return nil, err
		}
		if isFrontingAuthenticate {
			envoyRoute.TypedPerFilterConfig = map[string]*any.Any{
				"envoy.filters.http.ext_authz": disableExtAuthz,
			}
		} else {
			luaMetadata["remove_pomerium_cookie"] = &structpb.Value{
				Kind: &structpb.Value_StringValue{
					StringValue: options.CookieName,
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
			policyID, _ := policy.RouteID()
			for _, hdr := range b.reproxy.GetPolicyIDHeaders(policyID) {
				envoyRoute.RequestHeadersToAdd = append(envoyRoute.RequestHeadersToAdd,
					&envoy_config_core_v3.HeaderValueOption{
						Header: &envoy_config_core_v3.HeaderValue{
							Key:   hdr[0],
							Value: hdr[1],
						},
						AppendAction: envoy_config_core_v3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
					})
			}
		}

		envoyRoute.Metadata.FilterMetadata = map[string]*structpb.Struct{
			"envoy.filters.http.lua": {Fields: luaMetadata},
		}

		routes = append(routes, envoyRoute)
	}
	return routes, nil
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
	if urlutil.IsTCP(policy.Source.URL) {
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
	case urlutil.IsTCP(policy.Source.URL):
		match.PathSpecifier = &envoy_config_route_v3.RouteMatch_ConnectMatcher_{
			ConnectMatcher: &envoy_config_route_v3.RouteMatch_ConnectMatcher{},
		}
	case policy.Regex != "":
		match.PathSpecifier = &envoy_config_route_v3.RouteMatch_SafeRegex{
			SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
				EngineType: &envoy_type_matcher_v3.RegexMatcher_GoogleRe2{
					GoogleRe2: &envoy_type_matcher_v3.RegexMatcher_GoogleRE2{},
				},
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
		urlutil.IsTCP(policy.Source.URL) ||
		policy.IsForKubernetes() // disable for kubernetes so that tailing logs works (#2182)
}

func getRewriteOptions(policy *config.Policy) (prefixRewrite string, regexRewrite *envoy_type_matcher_v3.RegexMatchAndSubstitute) {
	if policy.PrefixRewrite != "" {
		prefixRewrite = policy.PrefixRewrite
	} else if policy.RegexRewritePattern != "" {
		regexRewrite = &envoy_type_matcher_v3.RegexMatchAndSubstitute{
			Pattern: &envoy_type_matcher_v3.RegexMatcher{
				EngineType: &envoy_type_matcher_v3.RegexMatcher_GoogleRe2{
					GoogleRe2: &envoy_type_matcher_v3.RegexMatcher_GoogleRE2{},
				},
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
					EngineType: &envoy_type_matcher_v3.RegexMatcher_GoogleRe2{
						GoogleRe2: &envoy_type_matcher_v3.RegexMatcher_GoogleRE2{},
					},
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
