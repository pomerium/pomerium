package envoyconfig

import (
	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	extensions_initial_metadata "github.com/pomerium/envoy-custom/api/extensions/transport_sockets/initial_metadata"

	"google.golang.org/protobuf/proto"
)

func configureConsoleRouteCluster(cluster *envoy_config_cluster_v3.Cluster) {
	wrapTransportSocket := func(socket *envoy_config_core_v3.TransportSocket) {
		wrappedTypedConfig := &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: marshalAny(&extensions_initial_metadata.Config{
				TransportSocket: proto.CloneOf(socket),
				Magic:           []byte{0x37, 0x32, 0x36, 0x31},
			}),
		}
		socket.Name = "pomerium.transport_sockets.initial_metadata"
		socket.ConfigType = wrappedTypedConfig
	}
	for i, match := range cluster.TransportSocketMatches {
		wrapTransportSocket(match.TransportSocket)
		if i == 0 {
			// We currently always set cluster.TransportSocket to the first entry in
			// TransportSocketMatches (they should point to the same object)
			if match.TransportSocket != cluster.TransportSocket {
				panic("bug: invalid cluster config: TransportSocket not set")
			}
		}
	}
}
