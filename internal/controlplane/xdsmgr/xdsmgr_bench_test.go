package xdsmgr

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"

	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/testutil"
)

// BenchmarkManagerChurn measures one config change on a stream to envoy, in
// which one cluster and the route configuration change: the manager diffs and
// sends the change, and envoy acknowledges each response.
func BenchmarkManagerChurn(b *testing.B) {
	for _, clusters := range []int{100, 1000, 10000} {
		for _, debug := range []bool{false, true} {
			b.Run(fmt.Sprintf("clusters=%d/debug=%t", clusters, debug), func(b *testing.B) {
				benchmarkManagerChurn(b, clusters, debug)
			})
		}
	}
}

func benchmarkManagerChurn(b *testing.B, clusters int, debug bool) {
	level := log.GetLevel()
	b.Cleanup(func() { log.SetLevel(level) })
	log.SetLevel(zerolog.InfoLevel)
	if debug {
		log.SetLevel(zerolog.DebugLevel)
	}
	log.Writer.Remove(os.Stdout)
	log.Writer.Add(io.Discard)
	b.Cleanup(func() {
		log.Writer.Remove(io.Discard)
		log.Writer.Add(os.Stdout)
	})

	handled := make(chan struct{}, 8)
	origOnHandleDeltaRequest := onHandleDeltaRequest
	b.Cleanup(func() { onHandleDeltaRequest = origOnHandleDeltaRequest })
	onHandleDeltaRequest = func(_ *streamState) { handled <- struct{}{} }

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

	mgr := NewManager(generations[0])
	cc := testutil.NewGRPCServer(b, func(s *grpc.Server) {
		envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(s, mgr)
	})
	ctx, cancel := context.WithCancel(b.Context())
	b.Cleanup(cancel)
	stream, err := envoy_service_discovery_v3.NewAggregatedDiscoveryServiceClient(cc).DeltaAggregatedResources(ctx)
	if err != nil {
		b.Fatal(err)
	}

	send := func(typeURL, nonce string) {
		if err := stream.Send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: typeURL, ResponseNonce: nonce}); err != nil {
			b.Fatal(err)
		}
		<-handled
	}
	// receive n responses and acknowledge each of them
	receiveAndACK := func(n int) {
		for range n {
			res, err := stream.Recv()
			if err != nil {
				b.Fatal(err)
			}
			send(res.GetTypeUrl(), res.GetNonce())
		}
	}

	// subscribe to every type and acknowledge the initial resources
	for _, typeURL := range []string{clusterTypeURL, listenerTypeURL, routeConfigurationTypeURL} {
		send(typeURL, "")
		receiveAndACK(1)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		mgr.Update(ctx, generations[(i+1)%2])
		// one response for the cluster, one for the route configuration
		receiveAndACK(2)
	}
}
