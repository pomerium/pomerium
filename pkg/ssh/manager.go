package ssh

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type activeStream struct {
	Handler          *StreamHandler
	Session          *string
	SessionBindingID *string
}

type StreamManager struct {
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

	sbrSyncer *sbrSyncer
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

func (sm *StreamManager) clearRecordsSbr(ctx context.Context) {
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
		slog.Info("watched a delete update from session.Session")
		// a session was deleted; terminate all of its associated streams
		for streamID := range sm.sessionStreams[record.Id] {
			log.Ctx(ctx).Debug().
				Str("session-id", record.Id).
				Uint64("stream-id", streamID).
				Msg("terminating stream: session revoked")
			slog.Info("session revoked from session.Session")
			sm.terminateStreamLocked(streamID)
		}
		delete(sm.sessionStreams, record.Id)
	}
}

func (sm *StreamManager) updateRecordsSbr(ctx context.Context, _ uint64, records []*databroker.Record) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	for _, record := range records {
		if record.DeletedAt == nil {
			continue
		}
		// a session was deleted; terminate all of its associated streams
		streams := sm.bindingStreams[record.Id]
		slog.With("bindingID", record.Id).With("managedStreams", len(streams)).Info("watched a delete update from session.SessionBinding")
		for streamID := range streams {
			log.Ctx(ctx).Debug().
				Str("session-id", record.Id).
				Uint64("stream-id", streamID).
				Msg("terminating stream: session revoked")
			slog.Info("session revoked from session.SessionBinding")
			sm.terminateStreamLocked(streamID)
		}
		delete(sm.bindingStreams, record.Id)
	}
}

func (sm *StreamManager) SetSessionIDForStream(streamID uint64, sessionID string, sessionBindingId string) error {
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
	if sm.bindingStreams[sessionBindingId] == nil {
		sm.bindingStreams[sessionBindingId] = map[uint64]struct{}{}
	}
	slog.With("streamID", streamID).With("sessionID", sessionID).With("sessionBindingId", sessionBindingId).Warn("updated ssh manager trackers")
	sm.sessionStreams[sessionID][streamID] = struct{}{}
	sm.bindingStreams[sessionBindingId][streamID] = struct{}{}
	sm.activeStreams[streamID].Session = &sessionID
	sm.activeStreams[streamID].SessionBindingID = &sessionBindingId
	return nil
}

type sbrSyncer struct {
	clientHandler func() databroker.DataBrokerServiceClient
	clearHandler  func(context.Context)
	updateHandler func(context.Context, uint64, []*databroker.Record)
}

var _ databroker.SyncerHandler = (*sbrSyncer)(nil)

func (sbr *sbrSyncer) ClearRecords(ctx context.Context) {
	sbr.clearHandler(ctx)
}

// GetDataBrokerServiceClient implements databroker.SyncerHandler.
func (sbr *sbrSyncer) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return sbr.clientHandler()
}

// UpdateRecords implements databroker.SyncerHandler.
func (sbr *sbrSyncer) UpdateRecords(ctx context.Context, serverVersion uint64, records []*databroker.Record) {
	sbr.updateHandler(ctx, serverVersion, records)
}

func NewStreamManager(auth AuthInterface, cfg *config.Config) *StreamManager {
	sm := &StreamManager{
		auth:               auth,
		waitForInitialSync: make(chan struct{}),
		reauthC:            make(chan struct{}, 1),
		cfg:                cfg,
		activeStreams:      map[uint64]*activeStream{},
		sessionStreams:     map[string]map[uint64]struct{}{},
		bindingStreams:     map[string]map[uint64]struct{}{},
	}

	sbrSyncer := &sbrSyncer{
		clientHandler: sm.GetDataBrokerServiceClient,
		clearHandler:  sm.clearRecordsSbr,
		updateHandler: sm.updateRecordsSbr,
	}

	sm.sbrSyncer = sbrSyncer
	return sm
}

func (sm *StreamManager) Run(ctx context.Context) error {

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
			sm.sbrSyncer,
			databroker.WithTypeURL("type.googleapis.com/session.SessionBinding"),
		)
		return syncer.Run(eCtx)
	})

	eg.Go(func() error {
		sm.reauthLoop(eCtx)
		return fmt.Errorf("reauth loop exiting")
	})

	return eg.Wait()
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
	_ context.Context,
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
			sm.onStreamHandlerClosed(streamID)
			close(writeC)
		},
	}
	sm.activeStreams[streamID] = &activeStream{
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
	if info.SessionBindingID != nil {
		bindingID := *info.SessionBindingID
		delete(sm.bindingStreams[bindingID], streamID)
		if len(sm.bindingStreams[bindingID]) == 0 {
			delete(sm.bindingStreams, bindingID)
		}
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
