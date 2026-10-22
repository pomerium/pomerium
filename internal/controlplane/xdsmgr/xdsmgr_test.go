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
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

const bufSize = 1024 * 1024

func TestManager(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Second*10)
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

// TestManager_LateACKOfRevertedUpdate covers an update that is reverted
// before envoy acknowledges it. Envoy applies the intermediate update, so the
// manager must re-send the reverted resources even though they are identical
// to the ones envoy acknowledged before.
//
// It does not run in parallel because it replaces onHandleDeltaRequest.
func TestManager_LateACKOfRevertedUpdate(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Second*10)
	defer clearTimeout()

	typeURL := "example.com/example"
	full := map[string][]*envoy_service_discovery_v3.Resource{
		typeURL: {
			{Name: "r1", Version: "1"},
			{Name: "r2", Version: "1"},
		},
	}
	partial := map[string][]*envoy_service_discovery_v3.Resource{
		typeURL: {
			{Name: "r1", Version: "1"},
		},
	}

	stateChanged := signal.New()
	origOnHandleDeltaRequest := onHandleDeltaRequest
	defer func() { onHandleDeltaRequest = origOnHandleDeltaRequest }()
	onHandleDeltaRequest = func(_ *streamState) {
		stateChanged.Broadcast(ctx)
	}

	srv := grpc.NewServer()
	mgr := NewManager(full)
	envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(srv, mgr)

	li := bufconn.Listen(bufSize)
	go func() { _ = srv.Serve(li) }()
	defer srv.Stop()

	cc, err := grpc.NewClient("passthrough:///test",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return li.Dial()
		}))
	require.NoError(t, err)
	defer func() { _ = cc.Close() }()

	client := envoy_service_discovery_v3.NewAggregatedDiscoveryServiceClient(cc)
	stream, err := client.DeltaAggregatedResources(ctx)
	require.NoError(t, err)

	ch := stateChanged.Bind()
	defer stateChanged.Unbind(ch)
	ack := func(nonce string) {
		t.Helper()
		require.NoError(t, stream.Send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{
			TypeUrl:       typeURL,
			ResponseNonce: nonce,
		}))
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ch:
		}
	}

	responses := make(chan *envoy_service_discovery_v3.DeltaDiscoveryResponse)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case responses <- msg:
			}
		}
	}()
	recv := func(timeout time.Duration) *envoy_service_discovery_v3.DeltaDiscoveryResponse {
		t.Helper()
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case msg := <-responses:
			return msg
		case <-time.After(timeout):
		}
		return nil
	}

	// envoy subscribes, receives the full set and acknowledges it
	ack("")
	msg := recv(time.Second * 5)
	require.NotNil(t, msg)
	assert.ElementsMatch(t, full[typeURL], msg.GetResources())
	ack(msg.GetNonce())

	// an update removes r2; envoy applies it but has not acknowledged it yet
	mgr.Update(ctx, partial)
	msg = recv(time.Second * 5)
	require.NotNil(t, msg)
	assert.Equal(t, []string{"r2"}, msg.GetRemovedResources())
	partialNonce := msg.GetNonce()

	// the next update restores r2 with the same version envoy acknowledged before
	mgr.Update(ctx, full)

	// envoy acknowledges the partial update after the manager has moved on
	ack(partialNonce)

	// envoy no longer has r2, so the manager must send it again
	msg = recv(time.Second * 2)
	require.NotNil(t, msg, "r2 was never re-sent after envoy applied its removal")
	assert.Equal(t, []*envoy_service_discovery_v3.Resource{
		{Name: "r2", Version: "1"},
	}, msg.GetResources())
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
