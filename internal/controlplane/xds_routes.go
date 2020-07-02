package controlplane

import (
	"fmt"

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
		buildControlPlanePathRoute("/robots.txt"),
		buildControlPlanePathRoute("/ping"),
		buildControlPlanePathRoute("/healthz"),
		buildControlPlanePathRoute("/.pomerium"),
		buildControlPlanePrefixRoute("/.pomerium/"),
		buildControlPlanePathRoute("/.well-known/pomerium"),
		buildControlPlanePrefixRoute("/.well-known/pomerium/"),
	}
	// if we're handling authentication, add the oauth2 callback url
	if config.IsAuthenticate(options.Services) && domain == options.GetAuthenticateURL().Host {
		routes = append(routes, buildControlPlanePathRoute(options.AuthenticateCallbackPath))
	}
	// if we're the proxy and this is the forward-auth url
	if config.IsProxy(options.Services) && options.ForwardAuthURL != nil && domain == options.ForwardAuthURL.Host {
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

func buildPolicyRoutes(options *config.Options, domain string) []*envoy_config_route_v3.Route {
	var routes []*envoy_config_route_v3.Route
	responseHeadersToAdd := make([]*envoy_config_core_v3.HeaderValueOption, 0, len(options.Headers))
	for k, v := range options.Headers {
		responseHeadersToAdd = append(responseHeadersToAdd, mkEnvoyHeader(k, v))
	}

	for i, policy := range options.Policies {
		if policy.Source.Host != domain {
			continue
		}

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
		clusterName := getPolicyName(&policy)

		requestHeadersToAdd := make([]*envoy_config_core_v3.HeaderValueOption, 0, len(policy.SetRequestHeaders))
		for k, v := range policy.SetRequestHeaders {
			requestHeadersToAdd = append(requestHeadersToAdd, mkEnvoyHeader(k, v))
		}

		requestHeadersToRemove := policy.RemoveRequestHeaders
		if !policy.PassIdentityHeaders {
			requestHeadersToRemove = append(requestHeadersToRemove, httputil.HeaderPomeriumJWTAssertion)
			for _, claim := range options.JWTClaimsHeaders {
				requestHeadersToRemove = append(requestHeadersToRemove, httputil.PomeriumJWTHeaderName(claim))
			}
		}

		var routeTimeout *durationpb.Duration
		if policy.AllowWebsockets {
			// disable the route timeout for websocket support
			routeTimeout = ptypes.DurationProto(0)
		} else {
			if policy.UpstreamTimeout != 0 {
				routeTimeout = ptypes.DurationProto(policy.UpstreamTimeout)
			} else {
				routeTimeout = ptypes.DurationProto(options.DefaultUpstreamTimeout)
			}
		}

		routeAction := &envoy_config_route_v3.RouteAction{
			ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
				Cluster: clusterName,
			},
			UpgradeConfigs: []*envoy_config_route_v3.RouteAction_UpgradeConfig{{
				UpgradeType: "websocket",
				Enabled:     &wrappers.BoolValue{Value: policy.AllowWebsockets},
			}},
			HostRewriteSpecifier: &envoy_config_route_v3.RouteAction_AutoHostRewrite{
				AutoHostRewrite: &wrappers.BoolValue{Value: !policy.PreserveHostHeader},
			},
			Timeout: routeTimeout,
		}
		if policy.Destination != nil && policy.Destination.Path != "" {
			routeAction.PrefixRewrite = policy.Destination.Path
		}
		route := &envoy_config_route_v3.Route{
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
			Action:                 &envoy_config_route_v3.Route_Route{Route: routeAction},
			RequestHeadersToAdd:    requestHeadersToAdd,
			RequestHeadersToRemove: requestHeadersToRemove,
			ResponseHeadersToAdd:   responseHeadersToAdd,
		}
		routes = append(routes, route)
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
