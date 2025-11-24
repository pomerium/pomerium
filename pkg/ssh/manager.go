package ssh

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/delta/v3"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/ssh/portforward"
)

type streamClusterEndpointDiscovery struct {
	self     *StreamManager
	streamID uint64
}

type streamEndpointsUpdate struct {
	streamID uint64
	added    map[string]portforward.RoutePortForwardInfo
	removed  map[string]struct{}
}

func (ed *streamClusterEndpointDiscovery) UpdateClusterEndpoints(added map[string]portforward.RoutePortForwardInfo, removed map[string]struct{}) {
	// run this callback in a separate goroutine, since it can deadlock if called
	// synchronously during startup
	ed.self.endpointsUpdateQueue <- streamEndpointsUpdate{
		streamID: ed.streamID,
		added:    added,
		removed:  removed,
	}
}

var ErrReauthDone = errors.New("reauth loop done")

type activeStream struct {
	Handler          *StreamHandler
	Session          *string
	SessionBindingID *string
	Endpoints        map[string]struct{}
}

type StreamManager struct {
	endpointv3.UnimplementedEndpointDiscoveryServiceServer
	ready              chan struct{}
	logger             *zerolog.Logger
	auth               AuthInterface
	reauthC            chan struct{}
	initialSyncDone    bool
	waitForInitialSync chan struct{}

	mu sync.Mutex

	cfg           *config.Config
	activeStreams map[uint64]*activeStream

	// Tracks stream IDs for active sessions
	sessionStreams map[string]map[uint64]struct{}

	// Tracks stream IDs per sessionBindingID for active sessions
	bindingStreams map[string]map[uint64]struct{}

	bindingSyncer *bindingSyncer
	// Tracks endpoint stream IDs for clusters
	clusterEndpoints     map[string]map[uint64]*extensions_ssh.EndpointMetadata
	endpointsUpdateQueue chan streamEndpointsUpdate
	edsCache             *cache.LinearCache
	edsServer            delta.Server
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

// DeltaEndpoints implements endpointv3.EndpointDiscoveryServiceServer.
func (sm *StreamManager) DeltaEndpoints(stream endpointv3.EndpointDiscoveryService_DeltaEndpointsServer) error {
	select {
	case <-stream.Context().Done():
		return context.Cause(stream.Context())
	case <-sm.ready:
	}
	log.Ctx(stream.Context()).Debug().Msg("delta endpoint stream started")
	defer log.Ctx(stream.Context()).Debug().Msg("delta endpoint stream ended")
	return sm.edsServer.DeltaStreamHandler(stream, resource.EndpointType)
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

func (sm *StreamManager) clearRecordsBinding(ctx context.Context) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if !sm.initialSyncDone {
		sm.initialSyncDone = true
		close(sm.waitForInitialSync)
		log.Ctx(ctx).Debug().
			Msg("ssh stream manager: initial sync done")
		return
	}
	for sessionID, streamIDs := range sm.bindingStreams {
		for streamID := range streamIDs {
			log.Ctx(ctx).Debug().
				Str("session-binding-id", sessionID).
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

func (sm *StreamManager) updateRecordsBinding(ctx context.Context, _ uint64, records []*databroker.Record) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for _, record := range records {
		if record.DeletedAt == nil {
			continue
		}
		// a session was deleted; terminate all of its associated streams
		streams := sm.bindingStreams[record.Id]
		for streamID := range streams {
			log.Ctx(ctx).Debug().
				Str("session-id", record.Id).
				Uint64("stream-id", streamID).
				Msg("terminating stream: session revoked")
			sm.terminateStreamLocked(streamID)
		}
		delete(sm.bindingStreams, record.Id)
	}
}

func (sm *StreamManager) SetSessionIDForStream(ctx context.Context, streamID uint64, sessionID string, sessionBindingID string) error {
	sm.mu.Lock()
	for !sm.initialSyncDone {
		sm.mu.Unlock()
		select {
		case <-sm.waitForInitialSync:
		case <-time.After(10 * time.Second):
			return errors.New("timed out waiting for initial sync")
		case <-ctx.Done():
			return context.Cause(ctx)
		}
		sm.mu.Lock()
	}
	defer sm.mu.Unlock()
	if sm.sessionStreams[sessionID] == nil {
		sm.sessionStreams[sessionID] = map[uint64]struct{}{}
	}
	if sm.bindingStreams[sessionBindingID] == nil {
		sm.bindingStreams[sessionBindingID] = map[uint64]struct{}{}
	}
	sm.sessionStreams[sessionID][streamID] = struct{}{}
	sm.bindingStreams[sessionBindingID][streamID] = struct{}{}
	sm.activeStreams[streamID].Session = &sessionID
	sm.activeStreams[streamID].SessionBindingID = &sessionBindingID
	return nil
}

type bindingSyncer struct {
	clientHandler func() databroker.DataBrokerServiceClient
	clearHandler  func(context.Context)
	updateHandler func(context.Context, uint64, []*databroker.Record)
}

var _ databroker.SyncerHandler = (*bindingSyncer)(nil)

func (sbr *bindingSyncer) ClearRecords(ctx context.Context) {
	sbr.clearHandler(ctx)
}

// GetDataBrokerServiceClient implements databroker.SyncerHandler.
func (sbr *bindingSyncer) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return sbr.clientHandler()
}

// UpdateRecords implements databroker.SyncerHandler.
func (sbr *bindingSyncer) UpdateRecords(ctx context.Context, serverVersion uint64, records []*databroker.Record) {
	sbr.updateHandler(ctx, serverVersion, records)
}

func NewStreamManager(ctx context.Context, auth AuthInterface, cfg *config.Config) *StreamManager {
	sm := &StreamManager{
		logger:               log.Ctx(ctx),
		auth:                 auth,
		ready:                make(chan struct{}),
		waitForInitialSync:   make(chan struct{}),
		reauthC:              make(chan struct{}, 1),
		cfg:                  cfg,
		activeStreams:        map[uint64]*activeStream{},
		sessionStreams:       map[string]map[uint64]struct{}{},
		clusterEndpoints:     map[string]map[uint64]*extensions_ssh.EndpointMetadata{},
		edsCache:             cache.NewLinearCache(resource.EndpointType),
		endpointsUpdateQueue: make(chan streamEndpointsUpdate, 128),
		bindingStreams:       map[string]map[uint64]struct{}{},
	}

	bindingSyncer := &bindingSyncer{
		clientHandler: sm.GetDataBrokerServiceClient,
		clearHandler:  sm.clearRecordsBinding,
		updateHandler: sm.updateRecordsBinding,
	}

	sm.bindingSyncer = bindingSyncer
	return sm
}

func (sm *StreamManager) Run(ctx context.Context) error {
	sm.edsServer = delta.NewServer(ctx, sm.edsCache, sm)
	eg, eCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		syncer := databroker.NewSyncer(
			eCtx,
			"ssh-auth-session-sync",
			sm,
			databroker.WithTypeURL("type.googleapis.com/session.Session"))
		return syncer.Run(eCtx)
	})

	eg.Go(func() error {
		syncer := databroker.NewSyncer(
			eCtx,
			"ssh-auth-session-binding-sync",
			sm.bindingSyncer,
			databroker.WithTypeURL("type.googleapis.com/session.SessionBinding"),
		)
		return syncer.Run(eCtx)
	})

	eg.Go(func() error {
		sm.reauthLoop(eCtx)
		return ErrReauthDone
	})
	eg.Go(func() error {
		sm.endpointsUpdateLoop(ctx)
		return nil
	})

	close(sm.ready)
	err := eg.Wait()
	if errors.Is(err, ErrReauthDone) {
		return nil
	}

	return err
}

func (sm *StreamManager) OnConfigChange(cfg *config.Config) {
	sm.mu.Lock()
	sm.cfg = cfg
	for _, s := range sm.activeStreams {
		s.Handler.portForwards.OnConfigUpdate(cfg)
	}
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
	_ context.Context,
	downstream *extensions_ssh.DownstreamConnectEvent,
) *StreamHandler {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	streamID := downstream.StreamId

	onClose := func() {
		sm.onStreamHandlerClosed(streamID)
	}
	discovery := &streamClusterEndpointDiscovery{
		self:     sm,
		streamID: streamID,
	}
	sh := NewStreamHandler(sm.auth, discovery, sm.cfg, downstream, onClose)
	sm.activeStreams[streamID] = &activeStream{
		Handler:   sh,
		Endpoints: map[string]struct{}{},
	}
	return sh
}

func (sm *StreamManager) onStreamHandlerClosed(streamID uint64) {
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
	if info.SessionBindingID != nil {
		bindingID := *info.SessionBindingID
		delete(sm.bindingStreams[bindingID], streamID)
		if len(sm.bindingStreams[bindingID]) == 0 {
			delete(sm.bindingStreams, bindingID)
		}
	}

	if len(info.Endpoints) > 0 {
		sm.logger.Debug().
			Uint64("stream-id", streamID).
			Any("endpoints", info.Endpoints).
			Msg("clearing endpoints for closed stream")
		sm.endpointsUpdateQueue <- streamEndpointsUpdate{
			streamID: streamID,
			removed:  info.Endpoints,
		}
	}
}

func (sm *StreamManager) processStreamEndpointsUpdate(update streamEndpointsUpdate) {
	// TODO: this may not scale well
	sm.mu.Lock()
	defer sm.mu.Unlock()
	streamID := update.streamID

	activeStream := sm.activeStreams[streamID] // can be nil

	toUpdate := map[string]types.Resource{} // *envoy_config_endpoint_v3.LbEndpoint
	toDelete := []string{}
	for clusterID, info := range update.added {
		if activeStream != nil {
			activeStream.Endpoints[clusterID] = struct{}{}
		}
		if _, ok := sm.clusterEndpoints[clusterID]; !ok {
			sm.clusterEndpoints[clusterID] = map[uint64]*extensions_ssh.EndpointMetadata{}
		}
		metadata := buildEndpointMetadata(info)
		sm.clusterEndpoints[clusterID][streamID] = metadata
		toUpdate[clusterID] = buildClusterLoadAssignment(clusterID, sm.clusterEndpoints[clusterID])
	}

	for clusterID := range update.removed {
		if activeStream != nil {
			delete(activeStream.Endpoints, clusterID)
		}
		delete(sm.clusterEndpoints[clusterID], streamID)
		if len(sm.clusterEndpoints[clusterID]) == 0 {
			delete(sm.clusterEndpoints, clusterID)
			toDelete = append(toDelete, clusterID)
		} else {
			toUpdate[clusterID] = buildClusterLoadAssignment(clusterID, sm.clusterEndpoints[clusterID])
		}
	}

	if err := sm.edsCache.UpdateResources(toUpdate, toDelete); err != nil {
		sm.logger.Err(err).Msg("error updating EDS resources")
	}
}

func buildClusterLoadAssignment(clusterID string, clusterEndpoints map[uint64]*extensions_ssh.EndpointMetadata) types.Resource {
	endpoints := []*envoy_config_endpoint_v3.LbEndpoint{}
	for streamID, metadata := range clusterEndpoints {
		endpoints = append(endpoints, buildLbEndpoint(streamID, metadata))
	}
	slices.SortFunc(endpoints, compareEndpoints)
	return &envoy_config_endpoint_v3.ClusterLoadAssignment{
		ClusterName: clusterID,
		Endpoints:   []*envoy_config_endpoint_v3.LocalityLbEndpoints{{LbEndpoints: endpoints}},
	}
}

func compareEndpoints(a, b *envoy_config_endpoint_v3.LbEndpoint) int {
	return cmp.Compare(
		a.GetEndpoint().GetAddress().GetSocketAddress().GetAddress(),
		b.GetEndpoint().GetAddress().GetSocketAddress().GetAddress())
}

func buildEndpointMetadata(info portforward.RoutePortForwardInfo) *extensions_ssh.EndpointMetadata {
	serverPort := info.Permission.ServerPort()
	return &extensions_ssh.EndpointMetadata{
		ServerPort: &extensions_ssh.ServerPort{
			Value:     serverPort.Value,
			IsDynamic: serverPort.IsDynamic,
		},
		MatchedPermission: &extensions_ssh.PortForwardPermission{
			RequestedHost: info.Permission.HostMatcher.InputPattern(),
			RequestedPort: info.Permission.RequestedPort,
		},
	}
}

func buildLbEndpoint(streamID uint64, metadata *extensions_ssh.EndpointMetadata) *envoy_config_endpoint_v3.LbEndpoint {
	endpointMdAny, _ := anypb.New(metadata)
	return &envoy_config_endpoint_v3.LbEndpoint{
		HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_Endpoint{
			Endpoint: &envoy_config_endpoint_v3.Endpoint{
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{
							Address: fmt.Sprintf("ssh:%d", streamID),
							PortSpecifier: &corev3.SocketAddress_PortValue{
								PortValue: metadata.ServerPort.Value,
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

func (sm *StreamManager) endpointsUpdateLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case update := <-sm.endpointsUpdateQueue:
			sm.processStreamEndpointsUpdate(update)
		}
	}
}

func (sm *StreamManager) terminateStreamLocked(streamID uint64) {
	if sh, ok := sm.activeStreams[streamID]; ok {
		sh.Handler.Terminate(status.Errorf(codes.PermissionDenied, "no longer authorized"))
	}
}
