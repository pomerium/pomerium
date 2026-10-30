package xdsmgr

import (
	"context"
	"encoding/hex"
	"fmt"
	"maps"
	"net"
	"sync/atomic"
	"testing"
	"time"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"hegel.dev/go/hegel"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/contextutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// testStream drives a manager over a gRPC stream as envoy would.
type testStream struct {
	t      testing.TB
	ctx    context.Context
	mgr    *Manager
	client envoy_service_discovery_v3.AggregatedDiscoveryServiceClient
	stream envoy_service_discovery_v3.AggregatedDiscoveryService_DeltaAggregatedResourcesClient
	queued chan int
}

// newTestStream serves the manager and opens a stream to it, with a deadline.
func newTestStream(t testing.TB, mgr *Manager) *testStream {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	return newTestStreamContext(ctx, t, mgr)
}

// newTestStreamContext serves the manager and opens a stream to it.
func newTestStreamContext(ctx context.Context, t testing.TB, mgr *Manager) *testStream {
	t.Helper()
	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(s, mgr)
	})
	return openTestStream(ctx, t, mgr, envoy_service_discovery_v3.NewAggregatedDiscoveryServiceClient(cc))
}

// openTestStream opens a stream to a manager the client already reaches.
func openTestStream(
	ctx context.Context,
	t testing.TB,
	mgr *Manager,
	client envoy_service_discovery_v3.AggregatedDiscoveryServiceClient,
) *testStream {
	t.Helper()
	queued := make(chan int, 16)
	mgr.onResponsesQueued = func(n int) { queued <- n }
	stream, err := client.DeltaAggregatedResources(ctx)
	require.NoError(t, err)
	return &testStream{t: t, ctx: ctx, mgr: mgr, client: client, stream: stream, queued: queued}
}

// settle returns the responses the manager queued in reaction to the last
// request or update.
func (s *testStream) settle() []*envoy_service_discovery_v3.DeltaDiscoveryResponse {
	s.t.Helper()
	var n int
	select {
	case <-s.ctx.Done():
		s.t.Fatal("the manager did not react")
	case n = <-s.queued:
	}
	responses := make([]*envoy_service_discovery_v3.DeltaDiscoveryResponse, 0, n)
	for range n {
		res, err := s.stream.Recv()
		require.NoError(s.t, err)
		responses = append(responses, res)
	}
	return responses
}

func (s *testStream) send(req *envoy_service_discovery_v3.DeltaDiscoveryRequest) []*envoy_service_discovery_v3.DeltaDiscoveryResponse {
	s.t.Helper()
	require.NoError(s.t, s.stream.Send(req))
	return s.settle()
}

func (s *testStream) update(resources map[string][]*envoy_service_discovery_v3.Resource) []*envoy_service_discovery_v3.DeltaDiscoveryResponse {
	s.t.Helper()
	s.mgr.Update(s.ctx, resources)
	return s.settle()
}

func (s *testStream) ack(typeURL, nonce string) []*envoy_service_discovery_v3.DeltaDiscoveryResponse {
	s.t.Helper()
	return s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: typeURL, ResponseNonce: nonce})
}

func (s *testStream) nack(typeURL, nonce, message string) []*envoy_service_discovery_v3.DeltaDiscoveryResponse {
	s.t.Helper()
	return s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{
		TypeUrl:       typeURL,
		ResponseNonce: nonce,
		ErrorDetail:   &status.Status{Code: int32(codes.Internal), Message: message},
	})
}

// resourceRefs lists the resources of the responses as name@version.
func resourceRefs(responses ...*envoy_service_discovery_v3.DeltaDiscoveryResponse) []string {
	var refs []string
	for _, res := range responses {
		for _, resource := range res.GetResources() {
			refs = append(refs, resource.GetName()+"@"+resource.GetVersion())
		}
	}
	return refs
}

func runHealthManager(t *testing.T, mgr *Manager, opts *config.Options) *healthv2.Manager {
	t.Helper()
	hm := healthv2.NewManager(healthv2.Options{PollInterval: 10 * time.Millisecond, CheckTimeout: time.Second})
	hm.RegisterHealthChecker(mgr)
	go hm.Run(t.Context())
	return hm
}

func TestManager(t *testing.T) {
	t.Parallel()

	typeURL := "example.com/example"
	s := newTestStream(t, NewManager(map[string][]*envoy_service_discovery_v3.Resource{
		typeURL: {{Name: "r1", Version: "1"}},
	}))

	t.Run("stream is disabled", func(t *testing.T) {
		stream, err := s.client.StreamAggregatedResources(s.ctx)
		require.NoError(t, err)
		_, err = stream.Recv()
		assert.Error(t, err, "only delta should be implemented")
		assert.Equal(t, codes.Unimplemented, grpcstatus.Code(err))
	})

	t.Run("updates", func(t *testing.T) {
		responses := s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: typeURL})
		require.Len(t, responses, 1)
		assert.NotEmpty(t, responses[0].GetNonce(), "nonce should not be empty")
		assert.Equal(t, []string{"r1@1"}, resourceRefs(responses...))
		s.ack(typeURL, responses[0].GetNonce())

		responses = s.update(map[string][]*envoy_service_discovery_v3.Resource{
			typeURL: {{Name: "r1", Version: "2"}},
		})
		require.Len(t, responses, 1)
		assert.Equal(t, []string{"r1@2"}, resourceRefs(responses...))
		s.ack(typeURL, responses[0].GetNonce())

		responses = s.update(map[string][]*envoy_service_discovery_v3.Resource{
			typeURL: nil,
		})
		require.Len(t, responses, 1)
		assert.Equal(t, []string{"r1"}, responses[0].GetRemovedResources())
	})
}

// TestManager_LateACKOfRevertedUpdate covers an update that is reverted
// before envoy acknowledges it. Envoy applies the intermediate update, so the
// manager must re-send the reverted resources even though they are identical
// to the ones envoy acknowledged before.
func TestManager_LateACKOfRevertedUpdate(t *testing.T) {
	t.Parallel()

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
	s := newTestStream(t, NewManager(full))

	// envoy subscribes, receives the full set and acknowledges it
	responses := s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: typeURL})
	require.Len(t, responses, 1)
	assert.ElementsMatch(t, []string{"r1@1", "r2@1"}, resourceRefs(responses...))
	s.ack(typeURL, responses[0].GetNonce())

	// an update removes r2; envoy applies it but has not acknowledged it yet
	responses = s.update(partial)
	require.Len(t, responses, 1)
	assert.Equal(t, []string{"r2"}, responses[0].GetRemovedResources())
	partialNonce := responses[0].GetNonce()

	// the next update restores r2 with the same version envoy acknowledged
	// before, and envoy acknowledges the partial update after the manager has
	// moved on
	responses = s.update(full)
	responses = append(responses, s.ack(typeURL, partialNonce)...)

	// envoy no longer has r2, so the manager must send it again
	assert.Equal(t, []string{"r2@1"}, resourceRefs(responses...),
		"r2 was never re-sent after envoy applied its removal")
}

// TestManager_ACKOfLastResponseSyncs covers an update that changes nothing
// for a type. The manager sends no response for it, so the last response for
// the type is the only one envoy can acknowledge. Acknowledging it must sync
// the type.
func TestManager_ACKOfLastResponseSyncs(t *testing.T) {
	t.Parallel()

	resources := map[string][]*envoy_service_discovery_v3.Resource{
		listenerTypeURL: {{Name: "r1", Version: "1"}},
	}
	mgr := NewManager(resources)
	s := newTestStream(t, mgr)

	responses := s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: listenerTypeURL})
	require.Len(t, responses, 1)
	_, info := mgr.Ready(t.Context())
	assert.Equal(t, "pending", info.Details["listener"])

	// an update that changes nothing for the type sends no response
	require.Empty(t, s.update(resources), "an unchanged type should not be re-sent")

	s.ack(listenerTypeURL, responses[0].GetNonce())
	_, info = mgr.Ready(t.Context())
	assert.Equal(t, "synced", info.Details["listener"],
		"acknowledging the last response for the type should sync it")
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

// TestManager_EnvoyHoldsLatestResources drives a manager with a simulated
// envoy. The envoy applies every response it receives, in order, and
// acknowledges each one, possibly much later and in any order across resource
// types. Whatever the order, once the manager has sent its responses to a
// change, envoy must hold exactly the latest resources.
//
// Every update lists every resource type, even with no resources, as
// Pomerium's own updates do for the types envoy subscribes to: the manager
// only diffs the types an update lists.
func TestManager_EnvoyHoldsLatestResources(t *testing.T) {
	t.Parallel()

	// each test case gets its own manager, so the stream of an earlier case
	// cannot react to a later case's changes
	srv := &caseManager{}
	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(s, srv)
	})
	client := envoy_service_discovery_v3.NewAggregatedDiscoveryServiceClient(cc)

	hegel.Test(t, func(ht *hegel.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()

		mgr := NewManager(nil)
		srv.current.Store(mgr)
		m := &xdsModel{
			ht:      ht,
			stream:  openTestStream(ctx, ht, mgr, client),
			latest:  map[string]map[string]string{},
			envoy:   map[string]map[string]string{},
			unacked: map[string][]string{},
		}
		for _, typeURL := range xdsModelTypes {
			m.envoy[typeURL] = map[string]string{}
			m.apply(m.stream.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: typeURL}))
		}
		hegel.RunStateful(ht, m)
	})
}

// caseManager serves the manager of the current test case.
type caseManager struct {
	envoy_service_discovery_v3.UnimplementedAggregatedDiscoveryServiceServer
	current atomic.Pointer[Manager]
}

func (c *caseManager) DeltaAggregatedResources(
	stream envoy_service_discovery_v3.AggregatedDiscoveryService_DeltaAggregatedResourcesServer,
) error {
	return c.current.Load().DeltaAggregatedResources(stream)
}

var xdsModelTypes = []string{"example.com/a", "example.com/b"}

// xdsModel is a simulated envoy on a stream to a manager.
type xdsModel struct {
	ht     *hegel.T
	stream *testStream

	// the versions the manager serves, by type and name
	latest map[string]map[string]string
	// the versions envoy holds, by type and name
	envoy map[string]map[string]string
	// the nonces of the responses envoy applied but has not acknowledged,
	// oldest first, by type
	unacked map[string][]string
}

// notef shows what happened in a failing test case.
func (m *xdsModel) notef(format string, args ...any) {
	m.ht.Note(fmt.Sprintf(format, args...))
}

// apply applies the responses as envoy does.
func (m *xdsModel) apply(responses []*envoy_service_discovery_v3.DeltaDiscoveryResponse) {
	for _, res := range responses {
		m.notef("envoy applies %s: %v, removes %v", res.GetTypeUrl(), resourceRefs(res), res.GetRemovedResources())
		held := m.envoy[res.GetTypeUrl()]
		for _, resource := range res.GetResources() {
			held[resource.GetName()] = resource.GetVersion()
		}
		for _, name := range res.GetRemovedResources() {
			delete(held, name)
		}
		m.unacked[res.GetTypeUrl()] = append(m.unacked[res.GetTypeUrl()], res.GetNonce())
	}
}

// RuleUpdate changes the resources the manager serves.
func (m *xdsModel) RuleUpdate(tc hegel.TestCase) {
	resources := map[string][]*envoy_service_discovery_v3.Resource{}
	for _, typeURL := range xdsModelTypes {
		latest := map[string]string{}
		resources[typeURL] = nil
		for _, name := range []string{"r1", "r2", "r3"} {
			if hegel.Draw(tc, hegel.Booleans()) {
				version := hegel.Draw(tc, hegel.SampledFrom([]string{"1", "2"}))
				latest[name] = version
				resources[typeURL] = append(resources[typeURL], &envoy_service_discovery_v3.Resource{Name: name, Version: version})
			}
		}
		m.latest[typeURL] = latest
	}
	m.notef("update: %v", m.latest)
	m.apply(m.stream.update(resources))
}

// RuleACK has envoy acknowledge its oldest unacknowledged response of one
// type.
func (m *xdsModel) RuleACK(tc hegel.TestCase) {
	var pending []string
	for _, typeURL := range xdsModelTypes {
		if len(m.unacked[typeURL]) > 0 {
			pending = append(pending, typeURL)
		}
	}
	if len(pending) == 0 {
		return
	}
	typeURL := hegel.Draw(tc, hegel.SampledFrom(pending))
	nonce := m.unacked[typeURL][0]
	m.unacked[typeURL] = m.unacked[typeURL][1:]
	m.notef("envoy acknowledges its oldest response of %s", typeURL)
	m.apply(m.stream.ack(typeURL, nonce))
}

// InvariantEnvoyHoldsLatest checks that envoy holds what the manager serves.
func (m *xdsModel) InvariantEnvoyHoldsLatest(_ hegel.TestCase) {
	for _, typeURL := range xdsModelTypes {
		if !maps.Equal(m.envoy[typeURL], m.latest[typeURL]) {
			m.ht.Fatalf("envoy holds %v of %s, the manager serves %v", m.envoy[typeURL], typeURL, m.latest[typeURL])
		}
	}
}

func TestXDSHealthChecks(t *testing.T) {
	t.Parallel()

	resources := map[string][]*envoy_service_discovery_v3.Resource{
		listenerTypeURL: {{Name: "r1", Version: "1"}},
	}

	t.Run("idle", func(t *testing.T) {
		t.Parallel()
		mgr := NewManager(resources)

		healthy, info := mgr.Healthy(t.Context())
		assert.False(t, healthy)
		assert.Equal(t, "no active stream", info.Reason)
	})

	t.Run("start", func(t *testing.T) {
		t.Parallel()
		mgr := NewManager(resources)
		s := newTestStream(t, mgr)
		s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: listenerTypeURL})

		ready, info := mgr.Ready(t.Context())
		assert.False(t, ready)
		assert.Equal(t, healthv2.Info{
			Reason:  "waiting for ACK: cluster, listener, route",
			Details: map[string]string{"cluster": "pending", "listener": "pending", "route": "pending"},
		}, info)
	})

	t.Run("ack", func(t *testing.T) {
		t.Parallel()
		mgr := NewManager(resources)
		s := newTestStream(t, mgr)
		responses := s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: listenerTypeURL})
		require.Len(t, responses, 1)

		s.ack(listenerTypeURL, responses[0].GetNonce())

		ready, info := mgr.Ready(t.Context())
		assert.False(t, ready)
		assert.Equal(t, healthv2.Info{
			Reason:  "waiting for ACK: cluster, route",
			Details: map[string]string{"cluster": "pending", "listener": "synced", "route": "pending"},
		}, info)
	})

	t.Run("nack", func(t *testing.T) {
		t.Parallel()
		mgr := NewManager(resources)
		s := newTestStream(t, mgr)
		responses := s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: listenerTypeURL})
		require.Len(t, responses, 1)

		s.nack(listenerTypeURL, responses[0].GetNonce(), "invalid listener")

		ready, info := mgr.Ready(t.Context())
		assert.False(t, ready)
		assert.Equal(t, healthv2.Info{
			Reason:  "waiting for ACK: cluster, route; listener NACK: invalid listener",
			Details: map[string]string{"cluster": "pending", "listener": "pending", "route": "pending"},
		}, info)
	})

	t.Run("nack_then_ack", func(t *testing.T) {
		t.Parallel()
		mgr := NewManager(resources)
		s := newTestStream(t, mgr)
		responses := s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: listenerTypeURL})
		require.Len(t, responses, 1)
		s.nack(listenerTypeURL, responses[0].GetNonce(), "invalid listener")

		responses = s.update(map[string][]*envoy_service_discovery_v3.Resource{
			listenerTypeURL: {{Name: "r1", Version: "2"}},
		})
		require.Len(t, responses, 1)
		s.ack(listenerTypeURL, responses[0].GetNonce())

		_, info := mgr.Ready(t.Context())
		assert.Equal(t, healthv2.Info{
			Reason:  "waiting for ACK: cluster, route",
			Details: map[string]string{"cluster": "pending", "listener": "synced", "route": "pending"},
		}, info)
	})

	t.Run("close", func(t *testing.T) {
		t.Parallel()
		mgr := NewManager(resources)
		s := newTestStream(t, mgr)
		s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: listenerTypeURL})

		require.NoError(t, s.stream.CloseSend())
		_, err := s.stream.Recv()
		require.Error(t, err)

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			healthy, info := mgr.Healthy(t.Context())
			assert.False(c, healthy)
			assert.Contains(c, info.Reason, "stream ended")
		}, 2*time.Second, 10*time.Millisecond)
	})

	t.Run("shutdown", func(t *testing.T) {
		t.Parallel()
		mgr := NewManager(resources)
		shutdownCtx, shutdown := context.WithCancelCause(t.Context())
		li := bufconn.Listen(1024 * 1024)
		srv := grpc.NewServer(grpc.StreamInterceptor(contextutil.ShutdownCauseStreamInterceptor(shutdownCtx)))
		envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(srv, mgr)
		go srv.Serve(li)
		t.Cleanup(srv.Stop)
		cc, err := grpc.NewClient("passthrough://bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return li.Dial() }),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		require.NoError(t, err)
		t.Cleanup(func() { cc.Close() })
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		t.Cleanup(cancel)
		s := openTestStream(ctx, t, mgr, envoy_service_discovery_v3.NewAggregatedDiscoveryServiceClient(cc))
		responses := s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: listenerTypeURL})
		require.Len(t, responses, 1)
		s.ack(listenerTypeURL, responses[0].GetNonce())
		readyBefore, readyInfoBefore := mgr.Ready(t.Context())
		healthyBefore, healthyInfoBefore := mgr.Healthy(t.Context())

		shutdown(fmt.Errorf("test: %w", contextutil.ErrShutdown))
		require.NoError(t, s.stream.CloseSend())
		_, err = s.stream.Recv()
		require.Error(t, err)

		require.True(t, healthyBefore)
		assert.Never(t, func() bool {
			ready, readyInfo := mgr.Ready(t.Context())
			healthy, healthyInfo := mgr.Healthy(t.Context())
			return ready != readyBefore || !assert.ObjectsAreEqual(readyInfoBefore, readyInfo) ||
				healthy != healthyBefore || !assert.ObjectsAreEqual(healthyInfoBefore, healthyInfo)
		}, 200*time.Millisecond, 10*time.Millisecond, "shutdown should not change readiness or health")
	})

	t.Run("reconnect", func(t *testing.T) {
		t.Parallel()
		mgr := NewManager(resources)
		s := newTestStream(t, mgr)
		responses := s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: listenerTypeURL})
		require.Len(t, responses, 1)
		s.ack(listenerTypeURL, responses[0].GetNonce())
		require.NoError(t, s.stream.CloseSend())
		_, err := s.stream.Recv()
		require.Error(t, err)

		s = openTestStream(s.ctx, t, mgr, s.client)
		s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: listenerTypeURL})

		ready, info := mgr.Ready(t.Context())
		assert.False(t, ready)
		assert.Equal(t, map[string]string{"cluster": "pending", "listener": "pending", "route": "pending"}, info.Details)
		healthy, _ := mgr.Healthy(t.Context())
		assert.True(t, healthy)
	})
}

func TestXDSHealthChecksDefaults(t *testing.T) {
	t.Parallel()

	defaults := config.New(config.NewDefaultOptions())
	defaults.GRPCPort = "10001"
	defaults.HTTPPort = "10002"
	defaults.OutboundPort = "10003"
	defaults.MetricsPort = "10004"
	withPolicies := defaults.Clone()
	for i := range 200 {
		to, err := config.ParseWeightedUrls(fmt.Sprintf("https://app-%d.internal", i))
		require.NoError(t, err)
		withPolicies.Options.Policies = append(withPolicies.Options.Policies, config.Policy{
			From: fmt.Sprintf("https://app-%d.example.com", i),
			To:   to,
		})
	}

	b := envoyconfig.New("local-connect", "local-grpc", "local-http", "local-debug", "local-metrics", filemgr.NewManager(), nil, true)
	resourcesByConfig := map[*config.Config]map[string][]*envoy_service_discovery_v3.Resource{}
	var routeConfigurationNames []string
	for _, cfg := range []*config.Config{defaults, withPolicies} {
		resources := map[string][]*envoy_service_discovery_v3.Resource{}
		clusters, err := b.BuildClusters(t.Context(), cfg)
		require.NoError(t, err)
		for _, c := range clusters {
			resources[clusterTypeURL] = append(resources[clusterTypeURL], &envoy_service_discovery_v3.Resource{
				Name: c.Name, Version: hex.EncodeToString(cryptutil.HashProto(c)), Resource: protoutil.NewAny(c),
			})
		}
		listeners, err := b.BuildListeners(t.Context(), cfg, false)
		require.NoError(t, err)
		for _, l := range listeners {
			resources[listenerTypeURL] = append(resources[listenerTypeURL], &envoy_service_discovery_v3.Resource{
				Name: l.Name, Version: hex.EncodeToString(cryptutil.HashProto(l)), Resource: protoutil.NewAny(l),
			})
		}
		routeConfigurations, err := b.BuildRouteConfigurations(t.Context(), cfg)
		require.NoError(t, err)
		for _, rc := range routeConfigurations {
			routeConfigurationNames = append(routeConfigurationNames, rc.Name)
			resources[routeConfigurationTypeURL] = append(resources[routeConfigurationTypeURL], &envoy_service_discovery_v3.Resource{
				Name: rc.Name, Version: hex.EncodeToString(cryptutil.HashProto(rc.Config)), Resource: protoutil.NewAny(rc.Config),
			})
		}
		resourcesByConfig[cfg] = resources
	}
	require.Greater(t, len(resourcesByConfig[withPolicies][clusterTypeURL]), len(resourcesByConfig[defaults][clusterTypeURL]))

	subscribe := []*envoy_service_discovery_v3.DeltaDiscoveryRequest{
		{TypeUrl: clusterTypeURL},
		{TypeUrl: listenerTypeURL},
		{TypeUrl: routeConfigurationTypeURL, ResourceNamesSubscribe: routeConfigurationNames},
	}
	syncAll := func(t *testing.T, s *testStream, hm *healthv2.Manager) {
		t.Helper()
		for _, req := range subscribe {
			responses := s.send(req)
			require.Len(t, responses, 1)
			s.ack(req.GetTypeUrl(), responses[0].GetNonce())
		}
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			snap := hm.Snapshot()
			assert.True(c, snap.Ready(), "%+v", snap.Checkers)
		}, 2*time.Second, 10*time.Millisecond)
	}

	t.Run("ready", func(t *testing.T) {
		t.Parallel()
		mgr := NewManager(resourcesByConfig[withPolicies])
		hm := runHealthManager(t, mgr, withPolicies.Options)
		syncAll(t, newTestStream(t, mgr), hm)
	})

	t.Run("update", func(t *testing.T) {
		t.Parallel()
		mgr := NewManager(resourcesByConfig[defaults])
		hm := runHealthManager(t, mgr, defaults.Options)
		s := newTestStream(t, mgr)
		syncAll(t, s, hm)

		responses := s.update(resourcesByConfig[withPolicies])
		require.NotEmpty(t, responses)
		assert.Never(t, func() bool { return !hm.Snapshot().Ready() }, 200*time.Millisecond, 10*time.Millisecond,
			"an unacknowledged config change should not affect readiness")

		for _, res := range responses {
			s.ack(res.GetTypeUrl(), res.GetNonce())
		}
		assert.Never(t, func() bool { return !hm.Snapshot().Ready() }, 200*time.Millisecond, 10*time.Millisecond,
			"an acknowledged config change should not affect readiness")
	})

	t.Run("update_nack", func(t *testing.T) {
		t.Parallel()
		mgr := NewManager(resourcesByConfig[defaults])
		hm := runHealthManager(t, mgr, defaults.Options)
		s := newTestStream(t, mgr)
		syncAll(t, s, hm)

		responses := s.update(resourcesByConfig[withPolicies])
		require.NotEmpty(t, responses)
		for _, res := range responses {
			s.nack(res.GetTypeUrl(), res.GetNonce(), "rejected")
		}

		ready, info := mgr.Ready(t.Context())
		assert.True(t, ready)
		for _, res := range responses {
			assert.Equal(t, "rejected", info.Details[typeName(res.GetTypeUrl())+".nack"], res.GetTypeUrl())
		}
		assert.Never(t, func() bool { return !hm.Snapshot().Ready() }, 200*time.Millisecond, 10*time.Millisecond,
			"a rejected config change should not affect readiness")
	})

	t.Run("earlier_ack", func(t *testing.T) {
		t.Parallel()
		mgr := NewManager(resourcesByConfig[withPolicies])
		hm := runHealthManager(t, mgr, withPolicies.Options)
		s := newTestStream(t, mgr)
		var initial []*envoy_service_discovery_v3.DeltaDiscoveryResponse
		for _, req := range subscribe {
			responses := s.send(req)
			require.Len(t, responses, 1)
			initial = append(initial, responses...)
		}
		latest := s.update(resourcesByConfig[defaults])
		require.NotEmpty(t, latest)

		for _, res := range initial {
			s.ack(res.GetTypeUrl(), res.GetNonce())
		}
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			snap := hm.Snapshot()
			assert.False(c, snap.Ready(), "superseded resources should not be ready: %+v", snap.Checkers)
		}, 2*time.Second, 10*time.Millisecond)

		for _, res := range latest {
			s.ack(res.GetTypeUrl(), res.GetNonce())
		}
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			snap := hm.Snapshot()
			assert.True(c, snap.Ready(), "%+v", snap.Checkers)
		}, 2*time.Second, 10*time.Millisecond)
	})

	t.Run("nack", func(t *testing.T) {
		t.Parallel()
		mgr := NewManager(resourcesByConfig[withPolicies])
		hm := runHealthManager(t, mgr, withPolicies.Options)
		s := newTestStream(t, mgr)

		responses := s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: clusterTypeURL})
		require.Len(t, responses, 1)
		s.ack(clusterTypeURL, responses[0].GetNonce())
		responses = s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: listenerTypeURL})
		require.Len(t, responses, 1)
		s.nack(listenerTypeURL, responses[0].GetNonce(), "invalid listener")

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			snap := hm.Snapshot()
			assert.False(c, snap.Ready(), "%+v", snap.Checkers)
			assert.True(c, snap.Healthy(), "%+v", snap.Checkers)
			if assert.Len(c, snap.Checkers, 1) {
				assert.Contains(c, snap.Checkers[0].Ready.Info.Reason, "listener NACK: invalid listener")
			}
		}, 2*time.Second, 10*time.Millisecond)
	})
}
