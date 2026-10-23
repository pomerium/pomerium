package xdsmgr

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/log"
)

// BenchmarkManagerChurn measures one config change on a stream to envoy, in
// which one cluster and the route configuration change: the manager diffs and
// sends the change, and envoy acknowledges each response, which makes the
// manager diff that type again.
func BenchmarkManagerChurn(b *testing.B) {
	for _, clusters := range []int{100, 1000, 10000} {
		for _, level := range []zerolog.Level{zerolog.InfoLevel, zerolog.DebugLevel} {
			b.Run(fmt.Sprintf("clusters=%d/log=%s", clusters, level), func(b *testing.B) {
				benchmarkManagerChurn(b, clusters, level)
			})
		}
	}
}

func benchmarkManagerChurn(b *testing.B, clusters int, level zerolog.Level) {
	prevLevel := log.GetLevel()
	log.SetLevel(level)
	log.Writer.Remove(os.Stdout)
	b.Cleanup(func() {
		log.SetLevel(prevLevel)
		log.Writer.Add(os.Stdout)
	})

	// two generations that differ in one cluster and the route configuration
	generation := func(gen int) map[string][]*envoy_service_discovery_v3.Resource {
		cs := make([]*envoy_service_discovery_v3.Resource, clusters)
		for i := range cs {
			cs[i] = &envoy_service_discovery_v3.Resource{Name: "cluster-" + strconv.Itoa(i), Version: "1"}
		}
		cs[0] = &envoy_service_discovery_v3.Resource{Name: "cluster-0", Version: strconv.Itoa(gen)}
		return map[string][]*envoy_service_discovery_v3.Resource{
			clusterTypeURL: cs,
			listenerTypeURL: {
				{Name: "https-ingress", Version: "1"},
				{Name: "grpc-ingress", Version: "1"},
			},
			routeConfigurationTypeURL: {{Name: "main", Version: strconv.Itoa(gen)}},
		}
	}
	generations := [2]map[string][]*envoy_service_discovery_v3.Resource{generation(0), generation(1)}

	s := newTestStreamContext(b.Context(), b, NewManager(generations[0]))
	ackAll := func(responses []*envoy_service_discovery_v3.DeltaDiscoveryResponse) {
		for _, res := range responses {
			s.ack(res.GetTypeUrl(), res.GetNonce())
		}
	}

	// subscribe to every type and acknowledge the initial resources
	for _, typeURL := range []string{clusterTypeURL, listenerTypeURL, routeConfigurationTypeURL} {
		ackAll(s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: typeURL}))
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		// one response for the cluster, one for the route configuration
		ackAll(s.update(generations[(i+1)%2]))
	}
}
