package xdsmgr

import (
	"context"
	"net"
	"testing"
	"time"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/test/bufconn"

	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

const bufSize = 1024 * 1024

func TestManager(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	defer clearTimeout()

	typeURL := "example.com/example"

	stateChanged := signal.New()
	origOnHandleDeltaRequest := onHandleDeltaRequest
	defer func() { onHandleDeltaRequest = origOnHandleDeltaRequest }()
	onHandleDeltaRequest = func(_ *streamState) {
		stateChanged.Broadcast(ctx)
	}

	srv := grpc.NewServer()
	mgr := NewManager(map[string][]*envoy_service_discovery_v3.Resource{
		typeURL: {
			{Name: "r1", Version: "1"},
		},
	})
	envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(srv, mgr)

	li := bufconn.Listen(bufSize)
	go func() { _ = srv.Serve(li) }()

	cc, err := grpc.Dial("test",
		grpc.WithInsecure(),
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return li.Dial()
		}))
	if !assert.NoError(t, err) {
		return
	}
	defer func() { _ = cc.Close() }()

	client := envoy_service_discovery_v3.NewAggregatedDiscoveryServiceClient(cc)
	t.Run("stream is disabled", func(t *testing.T) {
		stream, err := client.StreamAggregatedResources(ctx)
		if !assert.NoError(t, err) {
			return
		}
		_, err = stream.Recv()
		assert.Error(t, err, "only delta should be implemented")
		assert.Equal(t, codes.Unimplemented, grpc.Code(err))
	})

	t.Run("updates", func(t *testing.T) {
		stream, err := client.DeltaAggregatedResources(ctx)
		if !assert.NoError(t, err) {
			return
		}

		ch := stateChanged.Bind()
		defer stateChanged.Unbind(ch)
		ack := func(nonce string) {
			err = stream.Send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{
				TypeUrl:       typeURL,
				ResponseNonce: nonce,
			})
			assert.NoError(t, err)
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-ch:
			}
		}

		ack("")

		msg, err := stream.Recv()
		assert.NoError(t, err)
		assert.NotEmpty(t, msg.GetNonce(), "nonce should not be empty")
		assert.Equal(t, []*envoy_service_discovery_v3.Resource{
			{Name: "r1", Version: "1"},
		}, msg.GetResources())
		ack(msg.Nonce)

		mgr.Update(ctx, map[string][]*envoy_service_discovery_v3.Resource{
			typeURL: {{Name: "r1", Version: "2"}},
		})

		msg, err = stream.Recv()
		assert.NoError(t, err)
		assert.Equal(t, []*envoy_service_discovery_v3.Resource{
			{Name: "r1", Version: "2"},
		}, msg.GetResources())
		ack(msg.Nonce)

		mgr.Update(ctx, map[string][]*envoy_service_discovery_v3.Resource{
			typeURL: nil,
		})

		assert.Eventually(t, func() bool {
			msg, err = stream.Recv()
			require.NoError(t, err)
			ack(msg.Nonce)
			return assert.ObjectsAreEqual([]string{"r1"}, msg.GetRemovedResources())
		}, time.Second*5, time.Millisecond)
	})
}

func TestBuildDiscoveryResponsesForConsistentUpdates(t *testing.T) {
	t.Parallel()

	rc1 := protoutil.NewAny(&envoy_config_route_v3.RouteConfiguration{})
	l1 := protoutil.NewAny(&envoy_config_listener_v3.Listener{})
	c1 := protoutil.NewAny(&envoy_config_cluster_v3.Cluster{})

	responses := buildDiscoveryResponsesForConsistentUpdates([]*envoy_service_discovery_v3.DeltaDiscoveryResponse{
		{
			TypeUrl:          routeConfigurationTypeURL,
			Resources:        []*envoy_service_discovery_v3.Resource{{Name: "rc1", Resource: rc1}},
			RemovedResources: []string{"rc2"},
		},
		{
			TypeUrl:          listenerTypeURL,
			Resources:        []*envoy_service_discovery_v3.Resource{{Name: "l1", Resource: l1}},
			RemovedResources: []string{"l2"},
		},
		{
			TypeUrl:          clusterTypeURL,
			Resources:        []*envoy_service_discovery_v3.Resource{{Name: "c1", Resource: c1}},
			RemovedResources: []string{"c2"},
		},
	})
	testutil.AssertProtoEqual(t, []*envoy_service_discovery_v3.DeltaDiscoveryResponse{
		{
			TypeUrl:   clusterTypeURL,
			Resources: []*envoy_service_discovery_v3.Resource{{Name: "c1", Resource: c1}},
		},
		{
			TypeUrl:   listenerTypeURL,
			Resources: []*envoy_service_discovery_v3.Resource{{Name: "l1", Resource: l1}},
		},
		{
			TypeUrl:   routeConfigurationTypeURL,
			Resources: []*envoy_service_discovery_v3.Resource{{Name: "rc1", Resource: rc1}},
		},
		{
			TypeUrl:          routeConfigurationTypeURL,
			RemovedResources: []string{"rc2"},
		},
		{
			TypeUrl:          listenerTypeURL,
			RemovedResources: []string{"l2"},
		},
		{
			TypeUrl:          clusterTypeURL,
			RemovedResources: []string{"c2"},
		},
	}, responses)
}
