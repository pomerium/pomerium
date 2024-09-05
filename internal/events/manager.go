package events

import (
	"sync"

	"github.com/google/uuid"

	"github.com/pomerium/pomerium/internal/log"
)

// A Manager manages the dispatching of events to event sinks.
type Manager struct {
	mu    sync.RWMutex
	sinks map[EventSinkHandle]chan Event
}

// New creates a new Manager.
func New() *Manager {
	return &Manager{
		sinks: make(map[EventSinkHandle]chan Event),
	}
}

// Dispatch dispatches an event to any registered event sinks.
func (mgr *Manager) Dispatch(evt Event) {
	mgr.mu.RLock()
	dropped := mgr.dispatchLocked(evt)
	mgr.mu.RUnlock()

	if dropped {
		log.Error().
			Interface("event", evt).
			Msg("controlplane: dropping event due to full channel")
	}
}

func (mgr *Manager) dispatchLocked(evt Event) bool {
	sinks := make([]chan Event, 0, len(mgr.sinks))
	for _, sink := range mgr.sinks {
		sinks = append(sinks, sink)
	}

	dropped := false
	for _, sink := range sinks {
		select {
		case sink <- evt:
		default:
			dropped = true
		}
	}
	return dropped
}

// Register registers an event sink to receive events.
func (mgr *Manager) Register(sink EventSink) (handle EventSinkHandle) {
	handle = EventSinkHandle(uuid.NewString())
	ch := make(chan Event, 10)
	mgr.mu.Lock()
	mgr.sinks[handle] = ch
	mgr.mu.Unlock()
	go func() {
		for evt := range ch {
			sink(evt)
		}
	}()
	return handle
}

// Unregister unregisters an event sink so it no longer receives events.
func (mgr *Manager) Unregister(sinkHandle EventSinkHandle) {
	mgr.mu.Lock()
	sink, ok := mgr.sinks[sinkHandle]
	delete(mgr.sinks, sinkHandle)
	mgr.mu.Unlock()

	if ok {
		close(sink)
	}
}
