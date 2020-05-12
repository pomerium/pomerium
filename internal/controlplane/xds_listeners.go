package controlplane

import (
	"encoding/base64"
	"sort"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_filters_http_ext_authz_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	envoy_extensions_filters_http_lua_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	envoy_http_connection_manager "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/urlutil"
)

var disableExtAuthz *any.Any

func init() {
	disableExtAuthz, _ = ptypes.MarshalAny(&envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute{
		Override: &envoy_extensions_filters_http_ext_authz_v3.ExtAuthzPerRoute_Disabled{
			Disabled: true,
		},
	})
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

	luaConfig, _ := ptypes.MarshalAny(&envoy_extensions_filters_http_lua_v3.Lua{
		InlineCode: `
function envoy_on_request(request_handle)
  local headers = request_handle:headers()
  local dynamic_meta = request_handle:streamInfo():dynamicMetadata()
  if headers:get("x-pomerium-set-cookie") ~= nil then
    dynamic_meta:set("envoy.filters.http.lua", "pomerium_set_cookie", headers:get("x-pomerium-set-cookie"))
    headers:remove("x-pomerium-set-cookie")
  end
end

function envoy_on_response(response_handle)
  local headers = response_handle:headers()
  local dynamic_meta = response_handle:streamInfo():dynamicMetadata()
  local tbl = dynamic_meta:get("envoy.filters.http.lua")
  if tbl ~= nil and tbl["pomerium_set_cookie"] ~= nil then
    headers:add("set-cookie", tbl["pomerium_set_cookie"])
  end
end
`,
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
				Name: "envoy.filters.http.lua",
				ConfigType: &envoy_http_connection_manager.HttpFilter_TypedConfig{
					TypedConfig: luaConfig,
				},
			},
			{
				Name: "envoy.filters.http.router",
			},
		},
		AccessLog: srv.buildAccessLogs(options),
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

func (srv *Server) buildDownstreamTLSContext(options config.Options) *envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext {
	var cert envoy_extensions_transport_sockets_tls_v3.TlsCertificate
	if options.Cert != "" {
		bs, _ := base64.StdEncoding.DecodeString(options.Cert)
		cert.CertificateChain = &envoy_config_core_v3.DataSource{
			Specifier: &envoy_config_core_v3.DataSource_InlineBytes{
				InlineBytes: bs,
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
		bs, _ := base64.StdEncoding.DecodeString(options.Key)
		cert.PrivateKey = &envoy_config_core_v3.DataSource{
			Specifier: &envoy_config_core_v3.DataSource_InlineBytes{
				InlineBytes: bs,
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
			AlpnProtocols: []string{"h2", "http/1.1"},
		},
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
		if options.ForwardAuthURL != nil {
			lookup[urlutil.StripPort(options.ForwardAuthURL.Host)] = struct{}{}
		}
	}

	domains := make([]string, 0, len(lookup))
	for domain := range lookup {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	return domains
}
