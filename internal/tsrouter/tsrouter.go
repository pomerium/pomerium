package tsrouter

import (
	"context"
	"slices"
	"sync"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
)

// A TSRouter routes traffic from tailscale to Pomerium.
type TSRouter interface {
	OnConfigChange(cfg *config.Config)
	Run(ctx context.Context) error
}

// New returns a new tailscale router.
func New() TSRouter {
	return &tsRouter{}
}

type tsRouter struct {
	mu        sync.Mutex
	runCtx    context.Context
	cfg       *config.Config
	listeners []*tsListener
}

func (r *tsRouter) OnConfigChange(cfg *config.Config) {
	r.mu.Lock()
	r.cfg = cfg
	r.updateLocked()
	r.mu.Unlock()
}

func (r *tsRouter) Run(ctx context.Context) error {
	r.mu.Lock()
	r.runCtx = ctx
	r.updateLocked()
	r.mu.Unlock()

	<-ctx.Done()

	r.mu.Lock()
	r.runCtx = nil
	r.cfg = nil
	r.updateLocked()
	r.mu.Unlock()

	return context.Cause(ctx)
}

func (r *tsRouter) updateLocked() {
	if r.cfg == nil || r.runCtx == nil {
		for _, li := range r.listeners {
			li.Stop()
		}
		r.listeners = nil
		return
	}

	// start new or updated listeners
	for i, s := range r.cfg.Options.TailscaleListeners.Value {
		nl, err := newTSListener(r.cfg, s)
		if err != nil {
			log.Ctx(r.runCtx).Error().Err(err).Msg("tsrouter: error constructing listener")
			continue
		}
		if i >= len(r.listeners) {
			r.listeners = append(r.listeners, nl)
			nl.Start(r.runCtx)
		} else if !r.listeners[i].Equal(nl) {
			r.listeners[i].Stop()
			r.listeners[i] = nl
			nl.Start(r.runCtx)
		} else {
			r.listeners[i].certificates.Store(nl.certificates.Load())
		}
	}

	// stop any old listeners
	for i := len(r.cfg.Options.TailscaleListeners.Value); i < len(r.listeners); i++ {
		r.listeners[i].Stop()
		r.listeners[i] = nil
	}

	r.listeners = slices.DeleteFunc(r.listeners, func(l *tsListener) bool { return l == nil })
}
