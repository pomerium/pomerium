package controlplane

import (
	"fmt"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/golang/protobuf/ptypes/wrappers"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/urlutil"
)

func (srv *Server) buildGRPCRoutes() []*envoy_config_route_v3.Route {
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

func (srv *Server) buildPomeriumHTTPRoutes(options config.Options, domain string) []*envoy_config_route_v3.Route {
	routes := []*envoy_config_route_v3.Route{
		srv.buildControlPlanePathRoute("/ping"),
		srv.buildControlPlanePathRoute("/healthz"),
		srv.buildControlPlanePathRoute("/.pomerium"),
		srv.buildControlPlanePrefixRoute("/.pomerium/"),
	}
	// if we're handling authentication, add the oauth2 callback url
	if config.IsAuthenticate(options.Services) && domain == urlutil.StripPort(options.AuthenticateURL.Host) {
		routes = append(routes,
			srv.buildControlPlanePathRoute(options.AuthenticateCallbackPath))
	}
	// if we're the proxy and this is the forward-auth url
	if config.IsProxy(options.Services) && options.ForwardAuthURL != nil && domain == urlutil.StripPort(options.ForwardAuthURL.Host) {
		routes = append(routes,
			srv.buildControlPlanePrefixRoute("/"))
	}
	return routes
}

func (srv *Server) buildControlPlanePathRoute(path string) *envoy_config_route_v3.Route {
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

func (srv *Server) buildControlPlanePrefixRoute(prefix string) *envoy_config_route_v3.Route {
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

func (srv *Server) buildPolicyRoutes(options config.Options, domain string) []*envoy_config_route_v3.Route {
	var routes []*envoy_config_route_v3.Route
	for i, policy := range options.Policies {
		if policy.Source.Hostname() != domain {
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

		clusterName, _, _ := srv.getClusterDetails(policy.Destination)

		routes = append(routes, &envoy_config_route_v3.Route{
			Name:  fmt.Sprintf("policy-%d", i),
			Match: match,
			Action: &envoy_config_route_v3.Route_Route{
				Route: &envoy_config_route_v3.RouteAction{
					ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
						Cluster: clusterName,
					},
					UpgradeConfigs: []*envoy_config_route_v3.RouteAction_UpgradeConfig{{
						UpgradeType: "websocket",
						Enabled:     &wrappers.BoolValue{Value: policy.AllowWebsockets},
					}},
				},
			},
		})
	}
	return routes
}
