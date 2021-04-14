package xdsmgr

import (
	"sync"

	"github.com/pomerium/pomerium/pkg/grpc/registry"
)

const maxEvents = 5

var (
	globalEventsLock sync.Mutex
	globalEvents     []*registry.EnvoyConfigurationEvent
)

// AddEvent adds an envoy configuration event to the list of events.
func AddEvent(event *registry.EnvoyConfigurationEvent) {
	globalEventsLock.Lock()
	defer globalEventsLock.Unlock()

	// don't modify the original in place to avoid data races
	slc := append([]*registry.EnvoyConfigurationEvent{}, globalEvents...)
	slc = append(slc, event)
	for len(slc) > maxEvents {
		slc = slc[1:]
	}
	globalEvents = slc
}

// GetEvents gets a list of envoy configuration events.
func GetEvents() []*registry.EnvoyConfigurationEvent {
	globalEventsLock.Lock()
	defer globalEventsLock.Unlock()

	return globalEvents
}
