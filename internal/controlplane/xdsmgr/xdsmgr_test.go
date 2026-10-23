package xdsmgr

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"hegel.dev/go/hegel"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/health"
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

// recordingHealthProvider records whether each check was last reported
// running.
type recordingHealthProvider struct {
	mu     sync.Mutex
	checks map[health.Check]bool
}

func newRecordingHealthProvider() *recordingHealthProvider {
	return &recordingHealthProvider{checks: map[health.Check]bool{}}
}

func (p *recordingHealthProvider) ReportStatus(check health.Check, status health.Status, _ ...health.Attr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.checks[check] = status == health.StatusRunning
}

func (p *recordingHealthProvider) ReportError(check health.Check, _ error, _ ...health.Attr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.checks[check] = false
}

func (p *recordingHealthProvider) running(check health.Check) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.checks[check]
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

// TestManager_ACKOfLastResponseReportsRunning covers an update that changes
// nothing for a type. The manager sends no response for it, so the last
// response for the type is the only one envoy can acknowledge. Acknowledging
// it must report the type as running.
func TestManager_ACKOfLastResponseReportsRunning(t *testing.T) {
	t.Parallel()

	resources := map[string][]*envoy_service_discovery_v3.Resource{
		listenerTypeURL: {{Name: "r1", Version: "1"}},
	}
	provider := newRecordingHealthProvider()
	mgr := NewManager(resources)
	mgr.health = provider
	s := newTestStream(t, mgr)

	responses := s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: listenerTypeURL})
	require.Len(t, responses, 1)
	assert.False(t, provider.running(health.XDSListener))

	// an update that changes nothing for the type sends no response
	require.Empty(t, s.update(resources), "an unchanged type should not be re-sent")

	s.ack(listenerTypeURL, responses[0].GetNonce())
	assert.True(t, provider.running(health.XDSListener),
		"acknowledging the last response for the type should report it running")
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
			TypeUrl:          listenerTypeURL,
			Resources:        []*envoy_service_discovery_v3.Resource{{Name: "l1", Resource: l1}},
			RemovedResources: []string{"l2"},
		},
		{
			TypeUrl:          routeConfigurationTypeURL,
			Resources:        []*envoy_service_discovery_v3.Resource{{Name: "rc1", Resource: rc1}},
			RemovedResources: []string{"rc2"},
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

// TestManager_ListenerReplacedOnItsAddress covers an update that replaces a
// listener with one of another name on the same address. Envoy rejects a
// listener whose address another listener holds and applies the removals of
// each response before its additions. Once the manager has nothing more to
// send, envoy must hold the new listener.
func TestManager_ListenerReplacedOnItsAddress(t *testing.T) {
	t.Parallel()

	listener := func(name string) *envoy_service_discovery_v3.Resource {
		return &envoy_service_discovery_v3.Resource{
			Name:    name,
			Version: "1",
			Resource: protoutil.NewAny(&envoy_config_listener_v3.Listener{
				Name: name,
				Address: &envoy_config_core_v3.Address{Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Address:       "127.0.0.1",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{PortValue: 443},
					},
				}},
			}),
		}
	}
	s := newTestStream(t, NewManager(map[string][]*envoy_service_discovery_v3.Resource{
		listenerTypeURL: {listener("http-ingress")},
	}))

	// held is the name of the listener envoy holds on each address
	held := map[string]string{}
	heldNames := func() []string { return slices.Sorted(maps.Values(held)) }
	// apply applies the responses as envoy does, acknowledging or rejecting
	// each, until the manager sends nothing more
	apply := func(pending []*envoy_service_discovery_v3.DeltaDiscoveryResponse) {
		for len(pending) > 0 {
			res := pending[0]
			pending = pending[1:]
			for _, name := range res.GetRemovedResources() {
				maps.DeleteFunc(held, func(_, heldName string) bool { return heldName == name })
			}
			var rejected string
			for _, resource := range res.GetResources() {
				var li envoy_config_listener_v3.Listener
				require.NoError(t, resource.GetResource().UnmarshalTo(&li))
				address := li.GetAddress().GetSocketAddress().String()
				if other, taken := held[address]; taken && other != resource.GetName() {
					rejected = "error adding listener: '" + resource.GetName() + "' has duplicate address as existing listener"
					continue
				}
				held[address] = resource.GetName()
			}
			t.Logf("envoy applied nonce %s: added %v, removed %v, rejected %q, holds %v",
				res.GetNonce(), resourceRefs(res), res.GetRemovedResources(), rejected, heldNames())
			if rejected != "" {
				pending = append(pending, s.nack(res.GetTypeUrl(), res.GetNonce(), rejected)...)
			} else {
				pending = append(pending, s.ack(res.GetTypeUrl(), res.GetNonce())...)
			}
		}
	}

	apply(s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: listenerTypeURL}))
	require.Equal(t, []string{"http-ingress"}, heldNames())

	apply(s.update(map[string][]*envoy_service_discovery_v3.Resource{
		listenerTypeURL: {listener("https-ingress")},
	}))
	assert.Equal(t, []string{"https-ingress"}, heldNames(),
		"envoy must hold the listener that replaced the one on its address")
}

// TestManager_SubscribeIsAnswered covers requests that list a resource in
// resource_names_subscribe or resource_names_unsubscribe. The manager must
// send a subscribed resource, whether or not it was sent before, unless the
// request states the version envoy holds, and must not send an unsubscribed
// one.
func TestManager_SubscribeIsAnswered(t *testing.T) {
	t.Parallel()

	typeURL := "example.com/route-configuration"
	resources := map[string][]*envoy_service_discovery_v3.Resource{
		typeURL: {{Name: "main", Version: "1"}},
	}
	subscribe := &envoy_service_discovery_v3.DeltaDiscoveryRequest{
		TypeUrl:                typeURL,
		ResourceNamesSubscribe: []string{"main"},
	}
	unsubscribe := &envoy_service_discovery_v3.DeltaDiscoveryRequest{
		TypeUrl:                  typeURL,
		ResourceNamesUnsubscribe: []string{"main"},
	}
	// subscribed returns a stream on which envoy subscribed to main and
	// acknowledged it
	subscribed := func(t *testing.T) *testStream {
		s := newTestStream(t, NewManager(resources))
		responses := s.send(subscribe)
		require.Equal(t, []string{"main@1"}, resourceRefs(responses...))
		s.ack(typeURL, responses[0].GetNonce())
		return s
	}

	t.Run("subscribe again", func(t *testing.T) {
		t.Parallel()
		s := subscribed(t)

		assert.Equal(t, []string{"main@1"}, resourceRefs(s.send(subscribe)...),
			"a resource listed in resource_names_subscribe must be sent")
	})

	t.Run("unsubscribe then subscribe", func(t *testing.T) {
		t.Parallel()
		s := subscribed(t)

		assert.Empty(t, s.send(unsubscribe), "an unsubscribed resource must not be sent")
		assert.Empty(t, s.update(map[string][]*envoy_service_discovery_v3.Resource{
			typeURL: {{Name: "main", Version: "2"}},
		}), "an unsubscribed resource must not be sent when it changes")

		assert.Equal(t, []string{"main@2"}, resourceRefs(s.send(subscribe)...),
			"a resource listed in resource_names_subscribe must be sent")
	})

	t.Run("subscribe with the version held", func(t *testing.T) {
		t.Parallel()
		s := newTestStream(t, NewManager(resources))

		assert.Empty(t, s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{
			TypeUrl:                 typeURL,
			ResourceNamesSubscribe:  []string{"main"},
			InitialResourceVersions: map[string]string{"main": "1"},
		}), "a resource envoy holds at the latest version must not be sent")
	})

	t.Run("subscribe with an older version held", func(t *testing.T) {
		t.Parallel()
		s := newTestStream(t, NewManager(resources))

		assert.Equal(t, []string{"main@1"}, resourceRefs(s.send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{
			TypeUrl:                 typeURL,
			ResourceNamesSubscribe:  []string{"main"},
			InitialResourceVersions: map[string]string{"main": "0"},
		})...), "a resource envoy holds at an older version must be sent")
	})
}
