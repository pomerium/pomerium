package ssh

import (
	"sync"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
)

type StreamManager struct {
	auth          AuthInterface
	mu            sync.Mutex
	activeStreams map[uint64]*StreamHandler
}

func NewStreamManager(auth AuthInterface) *StreamManager {
	return &StreamManager{
		auth:          auth,
		activeStreams: map[uint64]*StreamHandler{},
	}
}

func (sm *StreamManager) LookupStream(streamID uint64) *StreamHandler {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	stream := sm.activeStreams[streamID]
	if stream == nil {
		return nil
	}
	return stream
}

func (sm *StreamManager) NewStreamHandler(cfg *config.Config, downstream *extensions_ssh.DownstreamConnectEvent) *StreamHandler {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	streamID := downstream.StreamId
	writeC := make(chan *extensions_ssh.ServerMessage, 32)
	sh := &StreamHandler{
		auth:       sm.auth,
		config:     cfg,
		downstream: downstream,
		readC:      make(chan *extensions_ssh.ClientMessage, 32),
		writeC:     writeC,
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
