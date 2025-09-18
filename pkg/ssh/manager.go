package ssh

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	loadstatsv3 "github.com/envoyproxy/go-control-plane/envoy/service/load_stats/v3"

	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/delta/v3"
	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type VirtualPort struct {
	Value     uint32
	IsDynamic bool
}

type EndpointDiscoveryInterface interface {
	SetClusterEndpointForStream(ctx context.Context, clusterID string, port VirtualPort)
	UnsetClusterEndpointForStream(ctx context.Context, clusterID string)
}

type VirtualPortAllocator interface {
	AllocateVirtualPort() (uint32, error)
	ReleaseVirtualPort(port uint32)
}

type streamClusterEndpointDiscovery struct {
	self     *StreamManager
	streamID uint64
}

func (ed *streamClusterEndpointDiscovery) SetClusterEndpointForStream(ctx context.Context, clusterID string, port VirtualPort) {
	ed.self.SetClusterEndpointForStream(ctx, ed.streamID, clusterID, port)
}

func (ed *streamClusterEndpointDiscovery) UnsetClusterEndpointForStream(ctx context.Context, clusterID string) {
	ed.self.UnsetClusterEndpointForStream(ctx, ed.streamID, clusterID)
}

type streamVirtualPortManager struct {
	self     *StreamManager
	streamID uint64
}

func (vm *streamVirtualPortManager) AllocateVirtualPort() (uint32, error) {
	vm.self.mu.Lock()
	defer vm.self.mu.Unlock()
	p, err := vm.self.vpa.Get()
	if err != nil {
		return 0, err
	}
	stream := vm.self.activeStreams[vm.streamID]
	stream.AllocatedPorts = append(stream.AllocatedPorts, uint32(p))
	return uint32(p), nil
}

func (vm *streamVirtualPortManager) ReleaseVirtualPort(port uint32) {
	vm.self.mu.Lock()
	defer vm.self.mu.Unlock()
	stream := vm.self.activeStreams[vm.streamID]
	vm.self.vpa.Put(uint(port))
	idx := slices.Index(stream.AllocatedPorts, port)
	stream.AllocatedPorts = slices.Delete(stream.AllocatedPorts, idx, idx+1)
}

type clusterLoadStatsHandler struct {
	watchedClusterIds []string
	sendC             chan []string
	running           atomic.Bool
	listenersMu       sync.Mutex
	statsListeners    map[string][]ClusterStatsListener
}

func newClusterLoadStatsHandler() *clusterLoadStatsHandler {
	return &clusterLoadStatsHandler{
		sendC: make(chan []string, 1),
	}
}

func (sh *clusterLoadStatsHandler) TrackedClustersUpdated(clusters map[string][]ClusterStatsListener) {
	if !sh.running.Load() {
		return
	}
	sh.listenersMu.Lock()
	sh.statsListeners = clusters
	clusterIds := slices.Sorted(maps.Keys(clusters))
	sh.listenersMu.Unlock()
	sh.sendC <- clusterIds
}

func (sh *clusterLoadStatsHandler) Run(stream loadstatsv3.LoadReportingService_StreamLoadStatsServer) error {
	sh.running.Store(true)
	defer sh.running.Store(false)
	eg, ctx := errgroup.WithContext(stream.Context())
	eg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case clusters := <-sh.sendC:
				if err := stream.Send(&loadstatsv3.LoadStatsResponse{
					Clusters:                  clusters,
					LoadReportingInterval:     durationpb.New(1 * time.Second),
					ReportEndpointGranularity: true,
				}); err != nil {
					return err
				}
			}
		}
	})
	eg.Go(func() error {
		for {
			stats, err := stream.Recv()
			if err != nil {
				return err
			}
			sh.listenersMu.Lock()
			for _, clusterStats := range stats.ClusterStats {
				for _, listener := range sh.statsListeners[clusterStats.ClusterName] {
					listener.HandleClusterStatsUpdate(clusterStats)
				}
			}
			sh.listenersMu.Unlock()
		}
	})
	return eg.Wait()
}

type activeStream struct {
	Handler        *StreamHandler
	Session        *string
	Cluster        *string
	AllocatedPorts []uint32
}

type updateListener interface {
	TrackedClustersUpdated(map[string][]ClusterStatsListener)
}

type StreamManager struct {
	endpointv3.UnimplementedEndpointDiscoveryServiceServer
	loadstatsv3.UnimplementedLoadReportingServiceServer
	auth               AuthInterface
	reauthC            chan struct{}
	initialSyncDone    bool
	waitForInitialSync chan struct{}

	mu sync.Mutex

	cfg           *config.Config
	activeStreams map[uint64]*activeStream
	vpa           *virtualPortSet

	// Tracks stream IDs for active sessions
	sessionStreams map[string]map[uint64]struct{}
	// Tracks endpoint stream IDs for clusters
	clusterEndpoints map[string]map[uint64]VirtualPort
	edsCache         *cache.LinearCache
	edsServer        delta.Server

	updateListeners      []updateListener
	cachedStatsListeners map[string][]ClusterStatsListener
}

// OnDeltaStreamClosed implements delta.Callbacks.
func (sm *StreamManager) OnDeltaStreamClosed(int64, *corev3.Node) {
}

// OnDeltaStreamOpen implements delta.Callbacks.
func (sm *StreamManager) OnDeltaStreamOpen(context.Context, int64, string) error {
	return nil
}

// OnStreamDeltaRequest implements delta.Callbacks.
func (sm *StreamManager) OnStreamDeltaRequest(_ int64, req *discoveryv3.DeltaDiscoveryRequest) error {
	if len(req.ResourceNamesSubscribe) == 0 {
		return nil
	}
	initialEmptyResources := make(map[string]types.Resource)
	for _, clusterID := range req.ResourceNamesSubscribe {
		initialEmptyResources[clusterID] = &envoy_config_endpoint_v3.ClusterLoadAssignment{
			ClusterName: clusterID,
		}
	}
	return sm.edsCache.UpdateResources(initialEmptyResources, nil)
}

// OnStreamDeltaResponse implements delta.Callbacks.
func (sm *StreamManager) OnStreamDeltaResponse(int64, *discoveryv3.DeltaDiscoveryRequest, *discoveryv3.DeltaDiscoveryResponse) {
}

const endpointTypeURL = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment"

func (sm *StreamManager) SetClusterEndpointForStream(ctx context.Context, streamID uint64, clusterID string, port VirtualPort) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.clusterEndpoints[clusterID] == nil {
		sm.clusterEndpoints[clusterID] = map[uint64]VirtualPort{}
		defer sm.notifyUpdateListenersLocked()
	}
	if sm.activeStreams[streamID].Cluster != nil {
		panic("bug: stream already assigned to cluster")
	}
	sm.clusterEndpoints[clusterID][streamID] = port
	sm.activeStreams[streamID].Cluster = &clusterID
	sm.rebuildClusterEndpointsLocked(ctx, clusterID)
}

func (sm *StreamManager) UnsetClusterEndpointForStream(ctx context.Context, streamID uint64, clusterID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.clusterEndpoints[clusterID] == nil ||
		sm.activeStreams[streamID] == nil ||
		sm.activeStreams[streamID].Cluster == nil ||
		*sm.activeStreams[streamID].Cluster != clusterID {
		panic("bug: UnsetClusterEndpointForStream called with invalid stream/cluster")
	}

	delete(sm.clusterEndpoints[clusterID], streamID)
	sm.activeStreams[streamID].Cluster = nil
	sm.rebuildClusterEndpointsLocked(ctx, clusterID)

	if len(sm.clusterEndpoints[clusterID]) == 0 {
		delete(sm.clusterEndpoints, clusterID)
		defer sm.notifyUpdateListenersLocked()
	}
}

func (sm *StreamManager) rebuildCachedStatsListenersLocked() {
	clear(sm.cachedStatsListeners)
	sm.cachedStatsListeners = make(map[string][]ClusterStatsListener, len(sm.clusterEndpoints))
	for clusterID := range sm.clusterEndpoints {
		for streamID := range sm.clusterEndpoints[clusterID] {
			activeStream, ok := sm.activeStreams[streamID]
			if !ok {
				panic("bug: active stream missing")
			}
			sm.cachedStatsListeners[clusterID] = append(sm.cachedStatsListeners[clusterID], activeStream.Handler)
		}
	}
}

func (sm *StreamManager) notifyUpdateListenersLocked() {
	sm.rebuildCachedStatsListenersLocked()
	for _, listener := range sm.updateListeners {
		listener.TrackedClustersUpdated(sm.cachedStatsListeners)
	}
}

func (sm *StreamManager) addUpdateListener(listener updateListener) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if slices.Contains(sm.updateListeners, listener) {
		panic("bug: updateListener added twice")
	}
	listener.TrackedClustersUpdated(sm.cachedStatsListeners)
	sm.updateListeners = append(sm.updateListeners, listener)
}

func (sm *StreamManager) removeUpdateListener(listener updateListener) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for i, l := range sm.updateListeners {
		if l == listener {
			sm.updateListeners = slices.Delete(sm.updateListeners, i, i+1)
			return
		}
	}
}

func (sm *StreamManager) rebuildClusterEndpointsLocked(ctx context.Context, clusterID string) {
	var endpoints []*envoy_config_endpoint_v3.LbEndpoint
	for streamID, virtualPort := range sm.clusterEndpoints[clusterID] {
		endpointMd := extensions_ssh.EndpointMetadata{
			IsDynamic: virtualPort.IsDynamic,
		}
		endpointMdAny, _ := anypb.New(&endpointMd)

		endpoints = append(endpoints, &envoy_config_endpoint_v3.LbEndpoint{
			HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
				Endpoint: &envoy_config_endpoint_v3.Endpoint{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{
								Address: fmt.Sprintf("ssh:%d", streamID),
								PortSpecifier: &corev3.SocketAddress_PortValue{
									PortValue: virtualPort.Value,
								},
							},
						},
					},
				},
			},
			Metadata: &corev3.Metadata{
				TypedFilterMetadata: map[string]*anypb.Any{
					"com.pomerium.ssh.endpoint": endpointMdAny,
				},
			},
			HealthStatus: corev3.HealthStatus_HEALTHY,
		})
	}
	slices.SortFunc(endpoints, func(a, b *envoy_config_endpoint_v3.LbEndpoint) int {
		return cmp.Compare(a.GetEndpointName(), b.GetEndpointName())
	})

	sm.edsCache.UpdateResource(clusterID, &envoy_config_endpoint_v3.ClusterLoadAssignment{
		ClusterName: clusterID,
		Endpoints: []*envoy_config_endpoint_v3.LocalityLbEndpoints{
			{
				LbEndpoints: endpoints,
			},
		},
	})
}

// DeltaEndpoints implements endpointv3.EndpointDiscoveryServiceServer.
func (sm *StreamManager) DeltaEndpoints(stream endpointv3.EndpointDiscoveryService_DeltaEndpointsServer) error {
	log.Ctx(stream.Context()).Debug().Msg("delta endpoint stream started")
	defer log.Ctx(stream.Context()).Debug().Msg("delta endpoint stream ended")
	return sm.edsServer.DeltaStreamHandler(stream, endpointTypeURL)
}

func (sm *StreamManager) StreamLoadStats(stream loadstatsv3.LoadReportingService_StreamLoadStatsServer) error {
	log.Ctx(stream.Context()).Debug().Msg("lrs stream started")
	defer log.Ctx(stream.Context()).Debug().Msg("lrs stream ended")

	handler := newClusterLoadStatsHandler()
	sm.addUpdateListener(handler)
	defer sm.removeUpdateListener(handler)
	return handler.Run(stream)
}

// ClearRecords implements databroker.SyncerHandler.
func (sm *StreamManager) ClearRecords(ctx context.Context) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if !sm.initialSyncDone {
		sm.initialSyncDone = true
		close(sm.waitForInitialSync)
		log.Ctx(ctx).Debug().
			Msg("ssh stream manager: initial sync done")
		return
	}
	for sessionID, streamIDs := range sm.sessionStreams {
		for streamID := range streamIDs {
			log.Ctx(ctx).Debug().
				Str("session-id", sessionID).
				Uint64("stream-id", streamID).
				Msg("terminating stream: databroker sync reset")
			sm.terminateStreamLocked(streamID)
		}
	}
	clear(sm.sessionStreams)
}

// GetDataBrokerServiceClient implements databroker.SyncerHandler.
func (sm *StreamManager) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return sm.auth.GetDataBrokerServiceClient()
}

// UpdateRecords implements databroker.SyncerHandler.
func (sm *StreamManager) UpdateRecords(ctx context.Context, _ uint64, records []*databroker.Record) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for _, record := range records {
		if record.DeletedAt == nil {
			continue
		}
		// a session was deleted; terminate all of its associated streams
		for streamID := range sm.sessionStreams[record.Id] {
			log.Ctx(ctx).Debug().
				Str("session-id", record.Id).
				Uint64("stream-id", streamID).
				Msg("terminating stream: session revoked")
			sm.terminateStreamLocked(streamID)
		}
		delete(sm.sessionStreams, record.Id)
	}
}

func (sm *StreamManager) SetSessionIDForStream(ctx context.Context, streamID uint64, sessionID string) error {
	lg := log.Ctx(ctx).Debug().
		Str("session-id", sessionID).
		Uint64("stream-id", streamID)
	lg.Msg("associating session ID with stream")
	sm.mu.Lock()
	for !sm.initialSyncDone {
		lg.Msg("waiting for initial sync")
		sm.mu.Unlock()
		select {
		case <-sm.waitForInitialSync:
			lg.Msg("initial sync done")
		case <-time.After(10 * time.Second):
			lg.Msg("timed out waiting for initial sync")
			return errors.New("timed out waiting for initial sync")
		}
		sm.mu.Lock()
	}
	defer sm.mu.Unlock()
	if sm.sessionStreams[sessionID] == nil {
		sm.sessionStreams[sessionID] = map[uint64]struct{}{}
	}
	sm.sessionStreams[sessionID][streamID] = struct{}{}
	sm.activeStreams[streamID].Session = &sessionID
	return nil
}

func NewStreamManager(auth AuthInterface, cfg *config.Config) *StreamManager {
	sm := &StreamManager{
		auth:               auth,
		waitForInitialSync: make(chan struct{}),
		reauthC:            make(chan struct{}, 1),
		cfg:                cfg,
		activeStreams:      map[uint64]*activeStream{},
		vpa:                NewVirtualPortSet(),
		sessionStreams:     map[string]map[uint64]struct{}{},
		clusterEndpoints:   map[string]map[uint64]VirtualPort{},
		edsCache:           cache.NewLinearCache(endpointTypeURL),
	}
	return sm
}

func (sm *StreamManager) Run(ctx context.Context) error {
	sm.edsServer = delta.NewServer(ctx, sm.edsCache, sm)

	syncer := databroker.NewSyncer(ctx, "ssh-auth-session-sync", sm,
		databroker.WithTypeURL("type.googleapis.com/session.Session"))
	reauthDone := make(chan struct{})
	ctx, ca := context.WithCancel(ctx)
	go func() {
		defer close(reauthDone)
		sm.reauthLoop(ctx)
	}()
	err := syncer.Run(ctx)
	ca()
	<-reauthDone
	return err
}

func (sm *StreamManager) OnConfigChange(cfg *config.Config) {
	sm.mu.Lock()
	sm.cfg = cfg
	sm.mu.Unlock()

	select {
	case sm.reauthC <- struct{}{}:
	default:
	}
}

func (sm *StreamManager) LookupStream(streamID uint64) *StreamHandler {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if info, ok := sm.activeStreams[streamID]; ok {
		return info.Handler
	}
	return nil
}

func (sm *StreamManager) NewStreamHandler(
	ctx context.Context,
	downstream *extensions_ssh.DownstreamConnectEvent,
) *StreamHandler {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	streamID := downstream.StreamId
	writeC := make(chan *extensions_ssh.ServerMessage, 32)
	sh := &StreamHandler{
		auth: sm.auth,
		discovery: &streamClusterEndpointDiscovery{
			self:     sm,
			streamID: streamID,
		},
		ports: &streamVirtualPortManager{
			self:     sm,
			streamID: streamID,
		},
		config:     sm.cfg,
		downstream: downstream,
		readC:      make(chan *extensions_ssh.ClientMessage, 32),
		writeC:     writeC,
		reauthC:    make(chan struct{}),
		terminateC: make(chan error, 1),
		close: func() {
			sm.onStreamHandlerClosed(ctx, streamID)
			close(writeC)
		},
	}
	sm.activeStreams[streamID] = &activeStream{
		Handler: sh,
	}
	return sh
}

func (sm *StreamManager) onStreamHandlerClosed(ctx context.Context, streamID uint64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	info := sm.activeStreams[streamID]
	delete(sm.activeStreams, streamID)
	if info.Session != nil {
		session := *info.Session
		delete(sm.sessionStreams[session], streamID)
		if len(sm.sessionStreams[session]) == 0 {
			delete(sm.sessionStreams, session)
		}
	}
	// release any allocated ports
	for _, vp := range info.AllocatedPorts {
		sm.vpa.Put(uint(vp))
	}
	if info.Cluster != nil {
		cluster := *info.Cluster
		delete(sm.clusterEndpoints[cluster], streamID)
		if len(sm.clusterEndpoints[cluster]) == 0 {
			delete(sm.clusterEndpoints, cluster)
		}
		sm.rebuildClusterEndpointsLocked(ctx, cluster)
	}
}

func (sm *StreamManager) reauthLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-sm.reauthC:
			sm.mu.Lock()
			snapshot := make([]*activeStream, 0, len(sm.activeStreams))
			for _, s := range sm.activeStreams {
				snapshot = append(snapshot, s)
			}
			sm.mu.Unlock()

			for _, s := range snapshot {
				s.Handler.Reauth()
			}
		}
	}
}

func (sm *StreamManager) terminateStreamLocked(streamID uint64) {
	if sh, ok := sm.activeStreams[streamID]; ok {
		sh.Handler.Terminate(status.Errorf(codes.PermissionDenied, "no longer authorized"))
	}
}
