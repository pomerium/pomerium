package controlplane

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/urlutil"

	envoy_config_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_access_loggers_grpc_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	envoy_extensions_filters_http_ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var disableExtAuthz *any.Any

func init() {
	disableExtAuthz, _ = ptypes.MarshalAny(&envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute{
		Override: &envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute_Disabled{
			Disabled: true,
		},
	})
}

func (srv *Server) buildDiscoveryResponse(version string, typeURL string, options config.Options) (*envoy_service_discovery_v3.DiscoveryResponse, error) {
	switch typeURL {
	case "type.googleapis.com/envoy.config.listener.v3.Listener":
		listeners := srv.buildListeners(options)
		anys := make([]*any.Any, len(listeners))
		for i, listener := range listeners {
			a, err := ptypes.MarshalAny(listener)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "error marshaling type to any: %v", err)
			}
			anys[i] = a
		}
		return &envoy_service_discovery_v3.DiscoveryResponse{
			VersionInfo: version,
			Resources:   anys,
			TypeUrl:     typeURL,
		}, nil
	case "type.googleapis.com/envoy.config.cluster.v3.Cluster":
		clusters := srv.buildClusters(options)
		anys := make([]*any.Any, len(clusters))
		for i, cluster := range clusters {
			a, err := ptypes.MarshalAny(cluster)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "error marshaling type to any: %v", err)
			}
			anys[i] = a
		}
		return &envoy_service_discovery_v3.DiscoveryResponse{
			VersionInfo: version,
			Resources:   anys,
			TypeUrl:     typeURL,
		}, nil
	default:
		return nil, status.Errorf(codes.Internal, "received request for unknown discovery request type: %s", typeURL)
	}
}

func (srv *Server) buildListeners(options config.Options) []*envoy_config_listener_v3.Listener {
	var listeners []*envoy_config_listener_v3.Listener

	if config.IsAuthenticate(options.Services) || config.IsProxy(options.Services) {
		listeners = append(listeners, srv.buildHTTPListener(options))
	}

	if config.IsAuthorize(options.Services) || config.IsCache(options.Services) {
		listeners = append(listeners, srv.buildGRPCListener(options))
	}

	return listeners
}

func (srv *Server) buildDownstreamTLSContext(options config.Options) *envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext {
	var cert envoy_extensions_transport_sockets_tls_v3.TlsCertificate
	if options.Cert != "" {
		cert.CertificateChain = &envoy_config_core_v3.DataSource{
			Specifier: &envoy_config_core_v3.DataSource_InlineString{
				InlineString: options.Cert,
			},
		}
	} else {
		cert.CertificateChain = &envoy_config_core_v3.DataSource{
			Specifier: &envoy_config_core_v3.DataSource_Filename{
				Filename: getAbsoluteFilePath(options.CertFile),
			},
		}
	}
	if options.Key != "" {
		cert.PrivateKey = &envoy_config_core_v3.DataSource{
			Specifier: &envoy_config_core_v3.DataSource_InlineString{
				InlineString: options.Key,
			},
		}
	} else {
		cert.PrivateKey = &envoy_config_core_v3.DataSource{
			Specifier: &envoy_config_core_v3.DataSource_Filename{
				Filename: getAbsoluteFilePath(options.KeyFile),
			},
		}
	}

	return &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
		CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
			TlsCertificates: []*envoy_extensions_transport_sockets_tls_v3.TlsCertificate{
				&cert,
			},
		},
	}
}

func (srv *Server) buildHTTPListener(options config.Options) *envoy_config_listener_v3.Listener {
	defaultPort := 80
	var transportSocket *envoy_config_core_v3.TransportSocket
	if !options.InsecureServer {
		defaultPort = 443
		tlsConfig, _ := ptypes.MarshalAny(srv.buildDownstreamTLSContext(options))
		transportSocket = &envoy_config_core_v3.TransportSocket{
			Name: "tls",
			ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
				TypedConfig: tlsConfig,
			},
		}
	}

	var virtualHosts []*envoy_config_route_v3.VirtualHost
	for _, domain := range srv.getAllRouteableDomains(options, options.Addr) {
		vh := &envoy_config_route_v3.VirtualHost{
			Name:    domain,
			Domains: []string{domain},
		}

		if options.Addr == options.GRPCAddr {
			// if this is a gRPC service domain and we're supposed to handle that, add those routes
			if (config.IsAuthorize(options.Services) && domain == urlutil.StripPort(options.AuthorizeURL.Host)) ||
				(config.IsCache(options.Services) && domain == urlutil.StripPort(options.CacheURL.Host)) {
				vh.Routes = append(vh.Routes, srv.buildGRPCRoutes()...)
			}
		}

		// these routes match /.pomerium/... and similar paths
		vh.Routes = append(vh.Routes, srv.buildPomeriumHTTPRoutes(options, domain)...)

		// if we're the proxy, add all the policy routes
		if config.IsProxy(options.Services) {
			vh.Routes = append(vh.Routes, srv.buildPolicyRoutes(options, domain)...)
		}

		if len(vh.Routes) > 0 {
			virtualHosts = append(virtualHosts, vh)
		}
	}

	extAuthZ, _ := ptypes.MarshalAny(&envoy_extensions_filters_http_ext_authz_v3.ExtAuthz{
		StatusOnError: &envoy_type_v3.HttpStatus{
			Code: envoy_type_v3.StatusCode_InternalServerError,
		},
		Services: &envoy_extensions_filters_http_ext_authz_v3.ExtAuthz_GrpcService{
			GrpcService: &envoy_config_core_v3.GrpcService{
				TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
						ClusterName: "pomerium-authz",
					},
				},
			},
		},
	})

	tc, _ := ptypes.MarshalAny(&envoy_http_connection_manager.HttpConnectionManager{
		CodecType:  envoy_http_connection_manager.HttpConnectionManager_AUTO,
		StatPrefix: "ingress",
		RouteSpecifier: &envoy_http_connection_manager.HttpConnectionManager_RouteConfig{
			RouteConfig: &envoy_config_route_v3.RouteConfiguration{
				Name:         "main",
				VirtualHosts: virtualHosts,
			},
		},
		HttpFilters: []*envoy_http_connection_manager.HttpFilter{
			{
				Name: "envoy.filters.http.ext_authz",
				ConfigType: &envoy_http_connection_manager.HttpFilter_TypedConfig{
					TypedConfig: extAuthZ,
				},
			},
			{
				Name: "envoy.filters.http.router",
			},
		},
		AccessLog: []*envoy_config_accesslog_v3.AccessLog{srv.buildAccessLog(options)},
	})

	li := &envoy_config_listener_v3.Listener{
		Name:    "http-ingress",
		Address: buildAddress(options.Addr, defaultPort),
		FilterChains: []*envoy_config_listener_v3.FilterChain{{
			Filters: []*envoy_config_listener_v3.Filter{
				{
					Name: "envoy.filters.network.http_connection_manager",
					ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
						TypedConfig: tc,
					},
				},
			},
			TransportSocket: transportSocket,
		}},
	}
	return li
}

func (srv *Server) buildAccessLog(options config.Options) *envoy_config_accesslog_v3.AccessLog {
	tc, _ := ptypes.MarshalAny(&envoy_extensions_access_loggers_grpc_v3.HttpGrpcAccessLogConfig{
		CommonConfig: &envoy_extensions_access_loggers_grpc_v3.CommonGrpcAccessLogConfig{
			LogName: "ingress-http",
			GrpcService: &envoy_config_core_v3.GrpcService{
				TargetSpecifier: &envoy_config_core_v3.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &envoy_config_core_v3.GrpcService_EnvoyGrpc{
						ClusterName: "pomerium-control-plane-grpc",
					},
				},
			},
		},
	})
	return &envoy_config_accesslog_v3.AccessLog{
		Name:       "envoy.access_loggers.http_grpc",
		ConfigType: &envoy_config_accesslog_v3.AccessLog_TypedConfig{TypedConfig: tc},
	}
}

func (srv *Server) buildGRPCListener(options config.Options) *envoy_config_listener_v3.Listener {
	defaultPort := 80
	var transportSocket *envoy_config_core_v3.TransportSocket
	if !options.GRPCInsecure {
		defaultPort = 443
		tlsConfig, _ := ptypes.MarshalAny(srv.buildDownstreamTLSContext(options))
		transportSocket = &envoy_config_core_v3.TransportSocket{
			Name: "tls",
			ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
				TypedConfig: tlsConfig,
			},
		}
	}

	tc, _ := ptypes.MarshalAny(&envoy_http_connection_manager.HttpConnectionManager{
		CodecType:  envoy_http_connection_manager.HttpConnectionManager_AUTO,
		StatPrefix: "grpc_ingress",
		RouteSpecifier: &envoy_http_connection_manager.HttpConnectionManager_RouteConfig{
			RouteConfig: &envoy_config_route_v3.RouteConfiguration{
				Name: "grpc",
				VirtualHosts: []*envoy_config_route_v3.VirtualHost{{
					Name:    "grpc",
					Domains: []string{"*"},
					Routes: []*envoy_config_route_v3.Route{{
						Name: "grpc",
						Match: &envoy_config_route_v3.RouteMatch{
							PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{Prefix: "/"},
							Grpc:          &envoy_config_route_v3.RouteMatch_GrpcRouteMatchOptions{},
						},
						Action: &envoy_config_route_v3.Route_Route{
							Route: &envoy_config_route_v3.RouteAction{
								ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{Cluster: "pomerium-control-plane-grpc"},
							},
						},
					}},
				}},
			},
		},
		HttpFilters: []*envoy_http_connection_manager.HttpFilter{{
			Name: "envoy.filters.http.router",
		}},
	})

	return &envoy_config_listener_v3.Listener{
		Name:    "grpc-ingress",
		Address: buildAddress(options.GRPCAddr, defaultPort),
		FilterChains: []*envoy_config_listener_v3.FilterChain{{
			Filters: []*envoy_config_listener_v3.Filter{{
				Name: "envoy.filters.network.http_connection_manager",
				ConfigType: &envoy_config_listener_v3.Filter_TypedConfig{
					TypedConfig: tc,
				},
			}},
			TransportSocket: transportSocket,
		}},
	}
}

func (srv *Server) getAllRouteableDomains(options config.Options, addr string) []string {
	lookup := map[string]struct{}{}
	if config.IsAuthenticate(options.Services) && addr == options.Addr {
		lookup[urlutil.StripPort(options.AuthenticateURL.Host)] = struct{}{}
	}
	if config.IsAuthorize(options.Services) && addr == options.GRPCAddr {
		lookup[urlutil.StripPort(options.AuthorizeURL.Host)] = struct{}{}
	}
	if config.IsCache(options.Services) && addr == options.GRPCAddr {
		lookup[urlutil.StripPort(options.CacheURL.Host)] = struct{}{}
	}
	if config.IsProxy(options.Services) && addr == options.Addr {
		for _, policy := range options.Policies {
			lookup[urlutil.StripPort(policy.Source.Host)] = struct{}{}
		}
	}

	domains := make([]string, 0, len(lookup))
	for domain := range lookup {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	return domains
}

func (srv *Server) buildPomeriumHTTPRoutes(options config.Options, domain string) []*envoy_config_route_v3.Route {
	action := &envoy_config_route_v3.Route_Route{
		Route: &envoy_config_route_v3.RouteAction{
			ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
				Cluster: "pomerium-control-plane-http",
			},
		},
	}
	routes := []*envoy_config_route_v3.Route{
		{
			Name: "dot-pomerium-path",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
					Path: "/.pomerium",
				},
			},
			Action: action,
			TypedPerFilterConfig: map[string]*any.Any{
				"envoy.filters.http.ext_authz": disableExtAuthz,
			},
		},
		{
			Name: "dot-pomerium-prefix",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{
					Prefix: "/.pomerium/",
				},
			},
			Action: action,
			TypedPerFilterConfig: map[string]*any.Any{
				"envoy.filters.http.ext_authz": disableExtAuthz,
			},
		},
	}
	// if we're handling authentication, add the oauth2 callback url
	if config.IsAuthenticate(options.Services) && domain == urlutil.StripPort(options.AuthenticateURL.Host) {
		routes = append(routes, &envoy_config_route_v3.Route{
			Name: "pomerium-authenticate-oauth2-callback",
			Match: &envoy_config_route_v3.RouteMatch{
				PathSpecifier: &envoy_config_route_v3.RouteMatch_Path{
					Path: options.AuthenticateCallbackPath,
				},
			},
			Action: action,
			TypedPerFilterConfig: map[string]*any.Any{
				"envoy.filters.http.ext_authz": disableExtAuthz,
			},
		})
	}
	return routes
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
				},
			},
		})
	}
	return routes
}

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

func (srv *Server) buildClusters(options config.Options) []*envoy_config_cluster_v3.Cluster {
	grpcURL := &url.URL{
		Scheme: "grpc",
		Host:   srv.GRPCListener.Addr().String(),
	}
	httpURL := &url.URL{
		Scheme: "http",
		Host:   srv.HTTPListener.Addr().String(),
	}
	authzURL := &url.URL{
		Scheme: strings.Replace(options.AuthorizeURL.Scheme, "http", "grpc", -1),
		Host:   options.AuthorizeURL.Host,
	}

	clusters := []*envoy_config_cluster_v3.Cluster{
		srv.buildCluster("pomerium-control-plane-grpc", grpcURL),
		srv.buildCluster("pomerium-control-plane-http", httpURL),
		srv.buildCluster("pomerium-authz", authzURL),
	}

	if config.IsProxy(options.Services) {
		type clusterDestination struct {
			name, scheme, hostport string
		}
		clusterDestinations := map[clusterDestination]struct{}{}
		for _, policy := range options.Policies {
			name, scheme, hostport := srv.getClusterDetails(policy.Destination)
			clusterDestinations[clusterDestination{name, scheme, hostport}] = struct{}{}
		}

		for dst := range clusterDestinations {
			name, scheme, hostport := dst.name, dst.scheme, dst.hostport
			clusters = append(clusters, srv.buildCluster(name, &url.URL{
				Scheme: scheme,
				Host:   hostport,
			}))
		}
	}

	return clusters
}

func (srv *Server) getClusterDetails(endpoint *url.URL) (name, scheme, hostport string) {
	name = endpoint.Scheme + "-" + strings.Replace(endpoint.Host, ":", "--", -1)
	return name, endpoint.Scheme, endpoint.Host
}

func (srv *Server) buildCluster(name string, endpoint *url.URL) *envoy_config_cluster_v3.Cluster {
	defaultPort := 80
	if endpoint.Scheme == "https" || endpoint.Scheme == "grpcs" {
		defaultPort = 443
	}

	cluster := &envoy_config_cluster_v3.Cluster{
		Name:           name,
		ConnectTimeout: ptypes.DurationProto(time.Second * 10),
		LoadAssignment: &envoy_config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: name,
			Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{{
				LbEndpoints: []*envoy_config_endpoint_v3.LbEndpoint{{
					HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
						Endpoint: &envoy_config_endpoint_v3.Endpoint{
							Address: buildAddress(endpoint.Host, defaultPort),
						},
					},
				}},
			}},
		},
		RespectDnsTtl: true,
	}

	if endpoint.Scheme == "grpc" {
		cluster.Http2ProtocolOptions = &envoy_config_core_v3.Http2ProtocolOptions{}
	}

	if endpoint.Scheme == "https" || endpoint.Scheme == "grpcs" {
		cluster.TransportSocket = &envoy_config_core_v3.TransportSocket{
			Name: "tls",
		}
	}

	if net.ParseIP(urlutil.StripPort(endpoint.Host)) == nil {
		cluster.ClusterDiscoveryType = &envoy_config_cluster_v3.Cluster_Type{Type: envoy_config_cluster_v3.Cluster_LOGICAL_DNS}
	} else {
		cluster.ClusterDiscoveryType = &envoy_config_cluster_v3.Cluster_Type{Type: envoy_config_cluster_v3.Cluster_STATIC}
	}

	return cluster
}

func buildAddress(hostport string, defaultPort int) *envoy_config_core_v3.Address {
	host, strport, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
		strport = fmt.Sprint(defaultPort)
	}
	port, err := strconv.Atoi(strport)
	if err != nil {
		port = defaultPort
	}
	if host == "" {
		host = "0.0.0.0"
	}
	return &envoy_config_core_v3.Address{
		Address: &envoy_config_core_v3.Address_SocketAddress{SocketAddress: &envoy_config_core_v3.SocketAddress{
			Address:       host,
			PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{PortValue: uint32(port)},
		}},
	}
}

func getAbsoluteFilePath(filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	}
	wd, _ := os.Getwd()
	return filepath.Join(wd, filename)
}
