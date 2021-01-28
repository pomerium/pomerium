package controlplane

import (
	"fmt"
	"net/url"
	"sort"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/golang/protobuf/ptypes"
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

func (srv *Server) buildGRPCRoutes() ([]*envoy_config_route_v3.Route, error) {
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

func (srv *Server) buildPomeriumHTTPRoutes(options *config.Options, domain string) ([]*envoy_config_route_v3.Route, error) {
	var routes []*envoy_config_route_v3.Route
	// enable ext_authz
	r, err := srv.buildControlPlanePathRoute("/.pomerium/jwt", true)
	if err != nil {
		return nil, err
	}
	routes = append(routes, r)

	// disable ext_authz and passthrough to proxy handlers
	r, err = srv.buildControlPlanePathRoute("/ping", false)
	if err != nil {
		return nil, err
	}
	routes = append(routes, r)
	r, err = srv.buildControlPlanePathRoute("/healthz", false)
	if err != nil {
		return nil, err
	}
	routes = append(routes, r)
	r, err = srv.buildControlPlanePathRoute("/.pomerium", false)
	if err != nil {
		return nil, err
	}
	routes = append(routes, r)
	r, err = srv.buildControlPlanePrefixRoute("/.pomerium/", false)
	if err != nil {
		return nil, err
	}
	routes = append(routes, r)
	r, err = srv.buildControlPlanePathRoute("/.well-known/pomerium", false)
	if err != nil {
		return nil, err
	}
	routes = append(routes, r)
	r, err = srv.buildControlPlanePrefixRoute("/.well-known/pomerium/", false)
	if err != nil {
		return nil, err
	}
	routes = append(routes, r)
	// per #837, only add robots.txt if there are no unauthenticated routes
	if !hasPublicPolicyMatchingURL(options, url.URL{Scheme: "https", Host: domain, Path: "/robots.txt"}) {
		r, err := srv.buildControlPlanePathRoute("/robots.txt", false)
		if err != nil {
			return nil, err
		}
		routes = append(routes, r)
	}
	// if we're handling authentication, add the oauth2 callback url
	authenticateURL, err := options.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}
	if config.IsAuthenticate(options.Services) && hostMatchesDomain(authenticateURL, domain) {
		r, err := srv.buildControlPlanePathRoute(options.AuthenticateCallbackPath, false)
		if err != nil {
			return nil, err
		}
		routes = append(routes, r)
	}
	// if we're the proxy and this is the forward-auth url
	forwardAuthURL, err := options.GetForwardAuthURL()
	if err != nil {
		return nil, err
	}
	if config.IsProxy(options.Services) && options.ForwardAuthURL != nil && hostMatchesDomain(forwardAuthURL, domain) {
		// disable ext_authz and pass request to proxy handlers that enable authN flow
		r, err := srv.buildControlPlanePathAndQueryRoute("/verify", []string{urlutil.QueryForwardAuthURI, urlutil.QuerySessionEncrypted, urlutil.QueryRedirectURI})
		if err != nil {
			return nil, err
		}
		routes = append(routes, r)
		r, err = srv.buildControlPlanePathAndQueryRoute("/", []string{urlutil.QueryForwardAuthURI, urlutil.QuerySessionEncrypted, urlutil.QueryRedirectURI})
		if err != nil {
			return nil, err
		}
		routes = append(routes, r)
		r, err = srv.buildControlPlanePathAndQueryRoute("/", []string{urlutil.QueryForwardAuthURI})
		if err != nil {
			return nil, err
		}
		routes = append(routes, r)

		// otherwise, enforce ext_authz; pass all other requests through to an upstream
		// handler that will simply respond with http status 200 / OK indicating that
		// the fronting forward-auth proxy can continue.
		r, err = srv.buildControlPlaneProtectedPrefixRoute("/")
		if err != nil {
			return nil, err
		}
		routes = append(routes, r)
	}
	return routes, nil
}

func (srv *Server) buildControlPlaneProtectedPrefixRoute(prefix string) (*envoy_config_route_v3.Route, error) {
	return &envoy_config_route_v3.Route{
		Name: "pomerium-protected-prefix-" + prefix,
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
	}, nil
}

func (srv *Server) buildControlPlanePathAndQueryRoute(path string, queryparams []string) (*envoy_config_route_v3.Route, error) {
	var queryParameterMatchers []*envoy_config_route_v3.QueryParameterMatcher
	for _, q := range queryparams {
		queryParameterMatchers = append(queryParameterMatchers,
			&envoy_config_route_v3.QueryParameterMatcher{
				Name:                         q,
				QueryParameterMatchSpecifier: &envoy_config_route_v3.QueryParameterMatcher_PresentMatch{PresentMatch: true},
			})
	}

	return &envoy_config_route_v3.Route{
		Name: "pomerium-path-and-query" + path,
		Match: &envoy_config_route_v3.RouteMatch{
			PathSpecifier:   &envoy_config_route_v3.RouteMatch_Path{Path: path},
			QueryParameters: queryParameterMatchers,
		},
		Action: &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{
				ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
					Cluster: httpCluster,
				},
			},
		},
		TypedPerFilterConfig: map[string]*any.Any{
			"envoy.filters.http.ext_authz": disableExtAuthz,
		},
	}, nil
}

func (srv *Server) buildControlPlanePathRoute(path string, protected bool) (*envoy_config_route_v3.Route, error) {
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
	return r, nil
}

func (srv *Server) buildControlPlanePrefixRoute(prefix string, protected bool) (*envoy_config_route_v3.Route, error) {
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
	return r, nil
}

var getPolicyName = func(policy *config.Policy) string {
	if policy.EnvoyOpts != nil && policy.EnvoyOpts.Name != "" {
		return policy.EnvoyOpts.Name
	}

	id, _ := policy.RouteID()
	return fmt.Sprintf("policy-%x", id)
}

func (srv *Server) buildPolicyRoutes(options *config.Options, domain string) ([]*envoy_config_route_v3.Route, error) {
	var routes []*envoy_config_route_v3.Route
	responseHeadersToAdd := toEnvoyHeaders(options.Headers)

	for i, p := range options.GetAllPolicies() {
		policy := p
		if !hostMatchesDomain(policy.Source.URL, domain) {
			continue
		}

		match := mkRouteMatch(&policy)
		requestHeadersToAdd := toEnvoyHeaders(policy.SetRequestHeaders)
		requestHeadersToRemove := getRequestHeadersToRemove(options, &policy)

		envoyRoute := &envoy_config_route_v3.Route{
			Name:  fmt.Sprintf("policy-%d", i),
			Match: match,
			Metadata: &envoy_config_core_v3.Metadata{
				FilterMetadata: map[string]*structpb.Struct{
					"envoy.filters.http.lua": {
						Fields: map[string]*structpb.Value{
							"remove_pomerium_cookie": {
								Kind: &structpb.Value_StringValue{
									StringValue: options.CookieName,
								},
							},
							"remove_pomerium_authorization": {
								Kind: &structpb.Value_BoolValue{
									BoolValue: true,
								},
							},
							"remove_impersonate_headers": {
								Kind: &structpb.Value_BoolValue{
									BoolValue: policy.KubernetesServiceAccountTokenFile != "" || policy.KubernetesServiceAccountToken != "",
								},
							},
						},
					},
				},
			},
			RequestHeadersToAdd:    requestHeadersToAdd,
			RequestHeadersToRemove: requestHeadersToRemove,
			ResponseHeadersToAdd:   responseHeadersToAdd,
		}
		if policy.Redirect != nil {
			action, err := srv.buildPolicyRouteRedirectAction(policy.Redirect)
			if err != nil {
				return nil, err
			}
			envoyRoute.Action = &envoy_config_route_v3.Route_Redirect{Redirect: action}
		} else {
			action, err := srv.buildPolicyRouteRouteAction(options, &policy)
			if err != nil {
				return nil, err
			}
			envoyRoute.Action = &envoy_config_route_v3.Route_Route{Route: action}
		}

		routes = append(routes, envoyRoute)
	}
	return routes, nil
}

func (srv *Server) buildPolicyRouteRedirectAction(r *config.PolicyRedirect) (*envoy_config_route_v3.RedirectAction, error) {
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

func (srv *Server) buildPolicyRouteRouteAction(options *config.Options, policy *config.Policy) (*envoy_config_route_v3.RouteAction, error) {
	clusterName := getPolicyName(policy)
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
		Append: &wrappers.BoolValue{Value: false},
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
		requestHeadersToRemove = append(requestHeadersToRemove, httputil.HeaderPomeriumJWTAssertion)
		for _, claim := range options.JWTClaimsHeaders {
			requestHeadersToRemove = append(requestHeadersToRemove, httputil.PomeriumJWTHeaderName(claim))
		}
	}
	return requestHeadersToRemove
}

func getRouteTimeout(options *config.Options, policy *config.Policy) *durationpb.Duration {
	var routeTimeout *durationpb.Duration
	if policy.UpstreamTimeout != 0 {
		routeTimeout = ptypes.DurationProto(policy.UpstreamTimeout)
	} else if policy.AllowWebsockets || urlutil.IsTCP(policy.Source.URL) {
		routeTimeout = ptypes.DurationProto(0)
	} else {
		routeTimeout = ptypes.DurationProto(options.DefaultUpstreamTimeout)
	}
	return routeTimeout
}

func getRouteIdleTimeout(policy *config.Policy) *durationpb.Duration {
	var idleTimeout *durationpb.Duration
	if policy.AllowWebsockets || urlutil.IsTCP(policy.Source.URL) {
		idleTimeout = ptypes.DurationProto(0)
	}
	return idleTimeout
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
