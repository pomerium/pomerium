package controlplane

import (
	"net"
	"net/url"
	"strings"
	"time"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	"github.com/golang/protobuf/ptypes"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/urlutil"
)

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
