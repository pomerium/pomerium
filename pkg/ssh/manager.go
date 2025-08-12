package ssh

import (
	"context"
	"errors"
	"sync"
	"time"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type StreamManager struct {
	auth               AuthInterface
	reauthC            chan struct{}
	initialSyncDone    bool
	waitForInitialSync chan struct{}

	mu            sync.Mutex
	cfg           *config.Config
	activeStreams map[uint64]*StreamHandler
	// Tracks session IDs for active streams
	activeStreamSessions map[uint64]string
	// Tracks stream IDs for active sessions
	sessionStreams map[string]map[uint64]struct{}
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
func (sm *StreamManager) UpdateRecords(ctx context.Context, serverVersion uint64, records []*databroker.Record) {
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
	sm.activeStreamSessions[streamID] = sessionID
	return nil
}

func NewStreamManager(ctx context.Context, auth AuthInterface, cfg *config.Config) *StreamManager {
	sm := &StreamManager{
		auth:                 auth,
		waitForInitialSync:   make(chan struct{}),
		reauthC:              make(chan struct{}, 1),
		cfg:                  cfg,
		activeStreams:        map[uint64]*StreamHandler{},
		activeStreamSessions: map[uint64]string{},
		sessionStreams:       map[string]map[uint64]struct{}{},
	}
	return sm
}

func (sm *StreamManager) Start(ctx context.Context) {
	syncer := databroker.NewSyncer(ctx, "ssh-auth-session-sync", sm,
		databroker.WithTypeURL("type.googleapis.com/session.Session"))
	go syncer.Run(ctx)
	go sm.reauthLoop(ctx)
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
	return sm.activeStreams[streamID]
}

func (sm *StreamManager) NewStreamHandler(
	downstream *extensions_ssh.DownstreamConnectEvent,
) *StreamHandler {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	streamID := downstream.StreamId
	writeC := make(chan *extensions_ssh.ServerMessage, 32)
	sh := &StreamHandler{
		auth:       sm.auth,
		config:     sm.cfg,
		downstream: downstream,
		readC:      make(chan *extensions_ssh.ClientMessage, 32),
		writeC:     writeC,
		reauthC:    make(chan struct{}),
		terminateC: make(chan error, 1),
		close: func() {
			sm.mu.Lock()
			defer sm.mu.Unlock()
			delete(sm.activeStreams, streamID)
			if sessionID, ok := sm.activeStreamSessions[streamID]; ok {
				delete(sm.sessionStreams[sessionID], streamID)
				if len(sm.sessionStreams[sessionID]) == 0 {
					delete(sm.sessionStreams, sessionID)
				}
			}
			delete(sm.activeStreamSessions, streamID)
			close(writeC)
		},
	}
	sm.activeStreams[streamID] = sh
	return sh
}

func (sm *StreamManager) reauthLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-sm.reauthC:
			sm.mu.Lock()
			snapshot := make([]*StreamHandler, 0, len(sm.activeStreams))
			for _, s := range sm.activeStreams {
				snapshot = append(snapshot, s)
			}
			sm.mu.Unlock()

			for _, s := range snapshot {
				s.Reauth()
			}
		}
	}
}

func (sm *StreamManager) terminateStreamLocked(streamID uint64) {
	if sh, ok := sm.activeStreams[streamID]; ok {
		sh.Terminate(status.Errorf(codes.PermissionDenied, "no longer authorized"))
	}
}
