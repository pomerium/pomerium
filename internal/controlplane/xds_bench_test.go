package controlplane

import (
	"encoding/hex"
	"fmt"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// newBenchRouteConfiguration builds a RouteConfiguration with numVirtualHosts
// virtual hosts and routesPerHost routes each, following the same
// Match/Action shape as Builder.buildPolicyRouteRouteAction and
// Builder.buildControlPlanePathRoute in config/envoyconfig/routes.go.
func newBenchRouteConfiguration(numVirtualHosts, routesPerHost int) *envoy_config_route_v3.RouteConfiguration {
	rc := &envoy_config_route_v3.RouteConfiguration{
		Name:             "https-ingress",
		ValidateClusters: wrapperspb.Bool(false),
	}
	for i := range numVirtualHosts {
		host := fmt.Sprintf("service-%d.corp.example.com", i)
		vh := &envoy_config_route_v3.VirtualHost{
			Name:    fmt.Sprintf("vh-%d", i),
			Domains: []string{host, host + ":*"},
		}
		for j := range routesPerHost {
			clusterName := fmt.Sprintf("route-%d-%d", i, j)
			vh.Routes = append(vh.Routes, &envoy_config_route_v3.Route{
				Name: fmt.Sprintf("route-%d-%d", i, j),
				Match: &envoy_config_route_v3.RouteMatch{
					PathSpecifier: &envoy_config_route_v3.RouteMatch_Prefix{Prefix: fmt.Sprintf("/api/v%d/", j)},
				},
				Decorator: &envoy_config_route_v3.Decorator{
					Operation: "ingress: ${method} ${host}${path}",
					Propagate: wrapperspb.Bool(false),
				},
				Metadata: &envoy_config_core_v3.Metadata{},
				Action: &envoy_config_route_v3.Route_Route{
					Route: &envoy_config_route_v3.RouteAction{
						ClusterSpecifier: &envoy_config_route_v3.RouteAction_Cluster{
							Cluster: clusterName,
						},
						Timeout:     durationpb.New(0),
						IdleTimeout: durationpb.New(0),
						UpgradeConfigs: []*envoy_config_route_v3.RouteAction_UpgradeConfig{
							{UpgradeType: "websocket", Enabled: wrapperspb.Bool(true)},
							{UpgradeType: "spdy/3.1", Enabled: wrapperspb.Bool(false)},
						},
						HashPolicy: []*envoy_config_route_v3.RouteAction_HashPolicy{{
							PolicySpecifier: &envoy_config_route_v3.RouteAction_HashPolicy_Header_{
								Header: &envoy_config_route_v3.RouteAction_HashPolicy_Header{
									HeaderName: "x-pomerium-routing-key",
								},
							},
							Terminal: true,
						}},
					},
				},
				ResponseHeadersToAdd: []*envoy_config_core_v3.HeaderValueOption{{
					Header: &envoy_config_core_v3.HeaderValue{
						Key:   "x-frame-options",
						Value: "SAMEORIGIN",
					},
				}},
			})
		}
		rc.VirtualHosts = append(rc.VirtualHosts, vh)
	}
	return rc
}

// BenchmarkDiscoveryResourceEncoding times the per-resource encode pattern
// used in Server.buildDiscoveryResources (internal/controlplane/xds.go):
// cryptutil.HashProto followed by protoutil.NewAny, both of which
// deterministically marshal the same message.
var (
	benchDiscoveryResourceVersionSink string
	benchDiscoveryResourceAnySink     *anypb.Any
)

func BenchmarkDiscoveryResourceEncoding(b *testing.B) {
	rc := newBenchRouteConfiguration(50, 20) // 1000 routes total

	b.ReportAllocs()
	for b.Loop() {
		benchDiscoveryResourceVersionSink = hex.EncodeToString(cryptutil.HashProto(rc))
		benchDiscoveryResourceAnySink = protoutil.NewAny(rc)
	}
}
