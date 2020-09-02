package controlplane

import (
	"fmt"
	"net/url"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
)

func buildGRPCRoutes() []*envoy_config_route_v3.Route {
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
	}}
}

func buildPomeriumHTTPRoutes(options *config.Options, domain string) []*envoy_config_route_v3.Route {
	routes := []*envoy_config_route_v3.Route{
		buildControlPlanePathRoute("/ping"),
		buildControlPlanePathRoute("/healthz"),
		buildControlPlanePathRoute("/.pomerium"),
		buildControlPlanePrefixRoute("/.pomerium/"),
		buildControlPlanePathRoute("/.well-known/pomerium"),
		buildControlPlanePrefixRoute("/.well-known/pomerium/"),
	}
	// per #837, only add robots.txt if there are no unauthenticated routes
	if !hasPublicPolicyMatchingURL(options, mustParseURL("https://"+domain+"/robots.txt")) {
		routes = append(routes, buildControlPlanePathRoute("/robots.txt"))
	}
	// if we're handling authentication, add the oauth2 callback url
	if config.IsAuthenticate(options.Services) && hostMatchesDomain(options.GetAuthenticateURL(), domain) {
		routes = append(routes, buildControlPlanePathRoute(options.AuthenticateCallbackPath))
	}
	// if we're the proxy and this is the forward-auth url
	if config.IsProxy(options.Services) && options.ForwardAuthURL != nil && hostMatchesDomain(options.GetForwardAuthURL(), domain) {
		routes = append(routes, buildControlPlanePrefixRoute("/"))
	}
	return routes
}

func buildControlPlanePathRoute(path string) *envoy_config_route_v3.Route {
	return &envoy_config_route_v3.Route{
		Name: "pomerium-path-" + path,
		Match: &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{Path: path},
		},
		Action: &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{
				ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
					Cluster: "pomerium-control-plane-http",
				},
			},
		},
		TypedPerFilterConfig: map[string]*any.Any{
			"envoy.filters.http.ext_authz": disableExtAuthz,
		},
	}
}

func buildControlPlanePrefixRoute(prefix string) *envoy_config_route_v3.Route {
	return &envoy_config_route_v3.Route{
		Name: "pomerium-prefix-" + prefix,
		Match: &envoy_config_route_v3.RouteMatch{
			PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{Prefix: prefix},
		},
		Action: &envoy_config_route_v3.Route_Route{
			Route: &envoy_config_route_v3.RouteAction{
				ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
					Cluster: "pomerium-control-plane-http",
				},
			},
		},
		TypedPerFilterConfig: map[string]*any.Any{
			"envoy.filters.http.ext_authz": disableExtAuthz,
		},
	}
}

var getPolicyName = func(policy *config.Policy) string {
	return fmt.Sprintf("policy-%x", policy.RouteID())
}

func buildPolicyRoutes(options *config.Options, domain string) []*envoy_config_route_v3.Route {
	var routes []*envoy_config_route_v3.Route
	responseHeadersToAdd := toEnvoyHeaders(options.Headers)

	for i, policy := range options.Policies {
		if !hostMatchesDomain(policy.Source.URL, domain) {
			continue
		}

		match := mkRouteMatch(&policy)
		clusterName := getPolicyName(&policy)
		requestHeadersToAdd := toEnvoyHeaders(policy.SetRequestHeaders)
		requestHeadersToRemove := getRequestHeadersToRemove(options, &policy)
		routeTimeout := getRouteTimeout(options, &policy)
		prefixRewrite := getPrefixRewrite(&policy)

		routes = append(routes, &envoy_config_route_v3.Route{
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
						},
					},
				},
			},
			Action: &envoy_config_route_v3.Route_Route{
				Route: &envoy_config_route_v3.RouteAction{
					ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
						Cluster: clusterName,
					},
					UpgradeConfigs: []*envoy_config_route_v3.RouteAction_UpgradeConfig{
						{
							UpgradeType: "websocket",
							Enabled:     &wrappers.BoolValue{Value: policy.AllowWebsockets},
						},
						{
							UpgradeType: "spdy/3.1",
							Enabled:     &wrappers.BoolValue{Value: policy.AllowSPDY},
						},
					},
					HostRewriteSpecifier: &envoy_config_route_v3.RouteAction_AutoHostRewrite{
						AutoHostRewrite: &wrappers.BoolValue{Value: !policy.PreserveHostHeader},
					},
					Timeout:       routeTimeout,
					PrefixRewrite: prefixRewrite,
				},
			},
			RequestHeadersToAdd:    requestHeadersToAdd,
			RequestHeadersToRemove: requestHeadersToRemove,
			ResponseHeadersToAdd:   responseHeadersToAdd,
		})
	}
	return routes
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
	envoyHeaders := make([]*envoy_config_core_v3.HeaderValueOption, 0, len(headers))
	for k, v := range headers {
		envoyHeaders = append(envoyHeaders, mkEnvoyHeader(k, v))
	}
	return envoyHeaders
}

func mkRouteMatch(policy *config.Policy) *envoy_config_route_v3.RouteMatch {
	match := &envoy_config_route_v3.RouteMatch{}
	switch {
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
	if policy.AllowWebsockets {
		if policy.UpstreamTimeout != 0 {
			routeTimeout = ptypes.DurationProto(policy.UpstreamTimeout)
		} else {
			// disable the default route timeout for websocket support
			routeTimeout = ptypes.DurationProto(0)
		}
	} else {
		if policy.UpstreamTimeout != 0 {
			routeTimeout = ptypes.DurationProto(policy.UpstreamTimeout)
		} else {
			routeTimeout = ptypes.DurationProto(options.DefaultUpstreamTimeout)
		}
	}
	return routeTimeout
}

func getPrefixRewrite(policy *config.Policy) string {
	prefixRewrite := ""
	if policy.Destination != nil && policy.Destination.Path != "" {
		prefixRewrite = policy.Destination.Path
	}
	return prefixRewrite
}

func hasPublicPolicyMatchingURL(options *config.Options, requestURL *url.URL) bool {
	for _, policy := range options.Policies {
		if policy.AllowPublicUnauthenticatedAccess && policy.Matches(requestURL) {
			return true
		}
	}
	return false
}

func mustParseURL(str string) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic(err)
	}
	return u
}
