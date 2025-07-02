package ssh

import (
	"context"
	"sync"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
)

type StreamManager struct {
	auth    AuthInterface
	reauthC chan struct{}

	mu            sync.Mutex
	cfg           *config.Config
	activeStreams map[uint64]*StreamHandler
}

func NewStreamManager(ctx context.Context, auth AuthInterface, cfg *config.Config) *StreamManager {
	sm := &StreamManager{
		auth:          auth,
		reauthC:       make(chan struct{}, 1),
		cfg:           cfg,
		activeStreams: map[uint64]*StreamHandler{},
	}
	go sm.reauthLoop(ctx)
	return sm
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
		close: func() {
			sm.mu.Lock()
			defer sm.mu.Unlock()
			delete(sm.activeStreams, streamID)
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
