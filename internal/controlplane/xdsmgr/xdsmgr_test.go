package xdsmgr

import (
	"context"
	"fmt"
	"maps"
	"net"
	"sync"
	"sync/atomic"
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
	"hegel.dev/go/hegel"

	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/health"
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

	mgr := NewManager(full)
	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(s, mgr)
	})

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
	recv := func(timeout time.Duration, failure string) *envoy_service_discovery_v3.DeltaDiscoveryResponse {
		t.Helper()
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case msg := <-responses:
			return msg
		case <-time.After(timeout):
			t.Fatal(failure)
		}
		return nil
	}

	// envoy subscribes, receives the full set and acknowledges it
	ack("")
	msg := recv(time.Second*5, "the initial resources were never sent")
	assert.ElementsMatch(t, full[typeURL], msg.GetResources())
	ack(msg.GetNonce())

	// an update removes r2; envoy applies it but has not acknowledged it yet
	mgr.Update(ctx, partial)
	msg = recv(time.Second*5, "the removal of r2 was never sent")
	assert.Equal(t, []string{"r2"}, msg.GetRemovedResources())
	partialNonce := msg.GetNonce()

	// the next update restores r2 with the same version envoy acknowledged before
	mgr.Update(ctx, full)

	// envoy acknowledges the partial update after the manager has moved on
	ack(partialNonce)

	// envoy no longer has r2, so the manager must send it again
	msg = recv(time.Second*2, "r2 was never re-sent after envoy applied its removal")
	assert.Equal(t, []*envoy_service_discovery_v3.Resource{
		{Name: "r2", Version: "1"},
	}, msg.GetResources())
}

// recordingHealthProvider records the status reported for each check.
type recordingHealthProvider struct {
	mu       sync.Mutex
	statuses map[health.Check]health.Status
}

func (p *recordingHealthProvider) ReportStatus(check health.Check, status health.Status, _ ...health.Attr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.statuses[check] = status
}

func (p *recordingHealthProvider) ReportError(check health.Check, _ error, _ ...health.Attr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.statuses[check] = health.StatusUnknown
}

func (p *recordingHealthProvider) status(check health.Check) health.Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.statuses[check]
}

// TestManager_ACKOfLastResponseReportsRunning covers an update that changes
// nothing for a type. The manager sends no response for it, so the last
// response for the type is the only one envoy can acknowledge. Acknowledging
// it must report the type as running.
//
// It does not run in parallel because it replaces onHandleDeltaRequest and
// registers a health provider.
func TestManager_ACKOfLastResponseReportsRunning(t *testing.T) {
	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Second*10)
	defer clearTimeout()

	resources := map[string][]*envoy_service_discovery_v3.Resource{
		listenerTypeURL: {{Name: "r1", Version: "1"}},
	}

	stateChanged := signal.New()
	origOnHandleDeltaRequest := onHandleDeltaRequest
	defer func() { onHandleDeltaRequest = origOnHandleDeltaRequest }()
	onHandleDeltaRequest = func(_ *streamState) {
		stateChanged.Broadcast(ctx)
	}

	provider := &recordingHealthProvider{statuses: map[health.Check]health.Status{}}
	health.GetProviderManager().Register("xdsmgr-test", provider)
	defer health.GetProviderManager().Deregister("xdsmgr-test")

	mgr := NewManager(resources)
	queued := make(chan int, 1)
	mgr.onResponsesQueued = func(n int) { queued <- n }
	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(s, mgr)
	})

	client := envoy_service_discovery_v3.NewAggregatedDiscoveryServiceClient(cc)
	stream, err := client.DeltaAggregatedResources(ctx)
	require.NoError(t, err)

	ch := stateChanged.Bind()
	defer stateChanged.Unbind(ch)
	ack := func(nonce string) {
		t.Helper()
		require.NoError(t, stream.Send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{
			TypeUrl:       listenerTypeURL,
			ResponseNonce: nonce,
		}))
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ch:
		}
	}

	ack("")
	<-queued
	msg, err := stream.Recv()
	require.NoError(t, err)
	assert.Equal(t, health.StatusUnknown, provider.status(health.XDSListener))

	// an update that changes nothing for the type sends no response
	mgr.Update(ctx, resources)
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case n := <-queued:
		require.Zero(t, n, "an unchanged type should not be re-sent")
	}

	ack(msg.GetNonce())
	assert.Equal(t, health.StatusRunning, provider.status(health.XDSListener),
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
// Pomerium's own updates do: the manager only diffs the types an update lists.
//
// It does not run in parallel, because TestManager replaces
// onHandleDeltaRequest, which every manager reads.
func TestManager_EnvoyHoldsLatestResources(t *testing.T) {
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

		queued := make(chan int, 1)
		mgr := NewManager(nil)
		mgr.onResponsesQueued = func(n int) { queued <- n }
		srv.current.Store(mgr)
		stream, err := client.DeltaAggregatedResources(ctx)
		require.NoError(ht, err)

		m := &xdsModel{
			ht:      ht,
			ctx:     ctx,
			mgr:     mgr,
			stream:  stream,
			queued:  queued,
			latest:  map[string]map[string]string{},
			envoy:   map[string]map[string]string{},
			unacked: map[string][]string{},
		}
		for _, typeURL := range xdsModelTypes {
			m.envoy[typeURL] = map[string]string{}
			require.NoError(ht, stream.Send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: typeURL}))
			m.settle()
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
	ctx    context.Context
	mgr    *Manager
	stream envoy_service_discovery_v3.AggregatedDiscoveryService_DeltaAggregatedResourcesClient
	queued <-chan int

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

func resourceRefsForNote(res *envoy_service_discovery_v3.DeltaDiscoveryResponse) []string {
	var refs []string
	for _, resource := range res.GetResources() {
		refs = append(refs, resource.GetName()+"@"+resource.GetVersion())
	}
	return refs
}

// settle receives the responses the manager queued for the last change or
// request, and applies them as envoy does.
func (m *xdsModel) settle() {
	var n int
	select {
	case n = <-m.queued:
	case <-m.ctx.Done():
		m.ht.Fatalf("the manager did not handle the change")
	}
	for range n {
		res, err := m.stream.Recv()
		if err != nil {
			m.ht.Fatalf("receiving a response: %v", err)
		}
		m.notef("envoy applies %s: %v, removes %v", res.GetTypeUrl(), resourceRefsForNote(res), res.GetRemovedResources())
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
	m.mgr.Update(m.ctx, resources)
	m.settle()
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
	err := m.stream.Send(&envoy_service_discovery_v3.DeltaDiscoveryRequest{TypeUrl: typeURL, ResponseNonce: nonce})
	if err != nil {
		m.ht.Fatalf("sending an ACK: %v", err)
	}
	m.settle()
}

// InvariantEnvoyHoldsLatest checks that envoy holds what the manager serves.
func (m *xdsModel) InvariantEnvoyHoldsLatest(_ hegel.TestCase) {
	for _, typeURL := range xdsModelTypes {
		if !maps.Equal(m.envoy[typeURL], m.latest[typeURL]) {
			m.ht.Fatalf("envoy holds %v of %s, the manager serves %v", m.envoy[typeURL], typeURL, m.latest[typeURL])
		}
	}
}
