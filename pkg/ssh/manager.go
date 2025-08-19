package ssh

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	endpointv3 "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"

	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/server/delta/v3"
	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type EndpointDiscoveryInterface interface {
	SetClusterEndpointForStream(clusterID string)
}

type streamClusterEndpointDiscovery struct {
	self     *StreamManager
	streamID uint64
}

func (ed *streamClusterEndpointDiscovery) SetClusterEndpointForStream(clusterID string) {
	ed.self.SetClusterEndpointForStream(ed.streamID, clusterID)
}

type activeStreamState struct {
	Handler *StreamHandler
	Session *string
	Cluster *string
}

type StreamManager struct {
	endpointv3.UnimplementedEndpointDiscoveryServiceServer
	auth               AuthInterface
	reauthC            chan struct{}
	initialSyncDone    bool
	waitForInitialSync chan struct{}

	mu            sync.Mutex
	cfg           *config.Config
	activeStreams map[uint64]*activeStreamState

	// Tracks stream IDs for active sessions
	sessionStreams map[string]map[uint64]struct{}
	// Tracks endpoint stream IDs for clusters
	clusterEndpoints map[string]map[uint64]struct{}
	edsCache         *cache.LinearCache
	edsServer        delta.Server
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

func (sm *StreamManager) SetClusterEndpointForStream(streamID uint64, clusterID string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sm.clusterEndpoints[clusterID] == nil {
		sm.clusterEndpoints[clusterID] = map[uint64]struct{}{}
	}
	if sm.activeStreams[streamID].Cluster != nil {
		// TODO: not sure if this should be possible?
		delete(sm.clusterEndpoints[*sm.activeStreams[streamID].Cluster], streamID)
	}
	sm.clusterEndpoints[clusterID][streamID] = struct{}{}
	sm.activeStreams[streamID].Cluster = &clusterID
	sm.rebuildClusterEndpointsLocked(clusterID)
}

func (sm *StreamManager) rebuildClusterEndpointsLocked(clusterID string) {
	var endpoints []*envoy_config_endpoint_v3.LbEndpoint
	for streamID := range sm.clusterEndpoints[clusterID] {
		endpoints = append(endpoints, &envoy_config_endpoint_v3.LbEndpoint{
			HostIdentifier: &envoy_config_endpoint_v3.LbEndpoint_EndpointName{
				EndpointName: fmt.Sprintf("ssh:%d", streamID),
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
	return sm.edsServer.DeltaStreamHandler(stream, endpointTypeURL)
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

func (sm *StreamManager) SetSessionIDForStream(streamID uint64, sessionID string) error {
	sm.mu.Lock()
	for !sm.initialSyncDone {
		sm.mu.Unlock()
		select {
		case <-sm.waitForInitialSync:
		case <-time.After(10 * time.Second):
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
		activeStreams:      map[uint64]*activeStreamState{},
		sessionStreams:     map[string]map[uint64]struct{}{},
		clusterEndpoints:   map[string]map[uint64]struct{}{},
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
		config:     sm.cfg,
		downstream: downstream,
		readC:      make(chan *extensions_ssh.ClientMessage, 32),
		writeC:     writeC,
		reauthC:    make(chan struct{}),
		terminateC: make(chan error, 1),
		close: func() {
			sm.onStreamHandlerClosed(streamID)
			close(writeC)
		},
	}
	sm.activeStreams[streamID] = &activeStreamState{
		Handler: sh,
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
	if info.Cluster != nil {
		cluster := *info.Cluster
		delete(sm.clusterEndpoints[cluster], streamID)
		if len(sm.clusterEndpoints[cluster]) == 0 {
			delete(sm.clusterEndpoints, cluster)
		}
		sm.rebuildClusterEndpointsLocked(cluster)
	}
}

func (sm *StreamManager) reauthLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-sm.reauthC:
			sm.mu.Lock()
			snapshot := make([]*activeStreamState, 0, len(sm.activeStreams))
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
