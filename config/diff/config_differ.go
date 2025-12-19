// Package diff provides incremental diffing of pomerium configuration.
package diff

import (
	"context"
	"sync/atomic"

	"github.com/pomerium/pomerium/config"
)

type RouteEventKind uint8

const (
	RouteDeleted RouteEventKind = iota
	RouteUpserted
)

type RouteEvent struct {
	Kind    RouteEventKind
	RouteID string
	Policy  *config.Policy // Only set for RouteUpserted
}

type OnRouteEvents func([]RouteEvent)

type ConfigDiffer struct {
	hashFn   func(*config.Policy) uint64
	filterFn func(*config.Policy) bool
	onEvents OnRouteEvents

	currentConfig atomic.Pointer[config.Config]
	wakeC         chan struct{}

	prev map[string]uint64 // routeID → hash
}

type Option func(*ConfigDiffer)

// WithHashFunc sets a custom hash function for determining route changes.
func WithHashFunc(fn func(*config.Policy) uint64) Option {
	return func(d *ConfigDiffer) {
		d.hashFn = fn
	}
}

// WithFilterFunc sets a custom filter function for selecting which policies
// to include in diff computations.
func WithFilterFunc(fn func(*config.Policy) bool) Option {
	return func(d *ConfigDiffer) {
		d.filterFn = fn
	}
}

func WithOnRouteEvents(fn OnRouteEvents) Option {
	return func(d *ConfigDiffer) {
		d.onEvents = fn
	}
}

func DefaultTunnelRouteHash(p *config.Policy) uint64 {
	return p.Checksum()
}

func DefaultTunnelRouteFilter(*config.Policy) bool {
	return true
}

func NewConfigDiffer(opts ...Option) *ConfigDiffer {
	d := &ConfigDiffer{
		hashFn:   DefaultTunnelRouteHash,
		filterFn: DefaultTunnelRouteFilter,
		wakeC:    make(chan struct{}, 1),
		prev:     make(map[string]uint64),
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

func (d *ConfigDiffer) OnConfigUpdated(cfg *config.Config) {
	d.currentConfig.Store(cfg)
	select {
	case d.wakeC <- struct{}{}:
	default:
	}
}

func (d *ConfigDiffer) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-d.wakeC:
			cfg := d.currentConfig.Load()
			if events := d.computeDiff(cfg); len(events) > 0 && d.onEvents != nil {
				d.onEvents(events)
			}
		}
	}
}

func (d *ConfigDiffer) computeDiff(cfg *config.Config) []RouteEvent {
	curr := make(map[string]uint64)
	currPolicies := make(map[string]*config.Policy)

	if cfg != nil && cfg.Options != nil {
		for p := range cfg.Options.GetAllPolicies() {
			if !d.filterFn(p) {
				continue
			}
			id := p.ID
			if id == "" {
				continue
			}
			curr[id] = d.hashFn(p)
			currPolicies[id] = p
		}
	}

	var events []RouteEvent

	for id := range d.prev {
		if _, ok := curr[id]; !ok {
			events = append(events, RouteEvent{
				Kind:    RouteDeleted,
				RouteID: id,
			})
		}
	}

	for id, h := range curr {
		oldH, existed := d.prev[id]
		if !existed || oldH != h {
			events = append(events, RouteEvent{
				Kind:    RouteUpserted,
				RouteID: id,
				Policy:  currPolicies[id],
			})
		}
	}

	d.prev = curr
	return events
}
