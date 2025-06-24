package ssh

import (
	"sync"

	oteltrace "go.opentelemetry.io/otel/trace"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type StreamManager struct {
	mu            sync.Mutex
	activeStreams map[uint64]*StreamHandler
}

func NewStreamManager() *StreamManager {
	return &StreamManager{
		activeStreams: map[uint64]*StreamHandler{},
	}
}

func (sm *StreamManager) LookupStream(streamID uint64) *StreamHandler {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	stream := sm.activeStreams[streamID]
	if stream == nil || !stream.IsExpectingInternalChannel() {
		return nil
	}
	return stream
}

func (sm *StreamManager) NewStreamHandler(
	currentConfig *atomicutil.Value[*config.Config],
	client databroker.DataBrokerServiceClient,
	evaluator PolicyEvaluator,
	tracerProvider oteltrace.TracerProvider,
	streamID uint64,
) *StreamHandler {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sh := &StreamHandler{
		auth:                NewAuth(evaluator, client, currentConfig, tracerProvider),
		currentConfig:       currentConfig,
		streamID:            streamID,
		pendingInfoResponse: make(chan chan *extensions_ssh.KeyboardInteractiveInfoPromptResponses, 1),
		readC:               make(chan *extensions_ssh.ClientMessage, 32),
		writeC:              make(chan *extensions_ssh.ServerMessage, 32),
		close: func() {
			sm.mu.Lock()
			defer sm.mu.Unlock()
			delete(sm.activeStreams, streamID)
		},
	}
	sm.activeStreams[streamID] = sh
	return sh
}
