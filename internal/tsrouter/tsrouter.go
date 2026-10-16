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

	sharedKey, err := r.cfg.Options.GetSharedKey()
	if err != nil {
		log.Ctx(r.runCtx).Error().Err(err).Msg("tsrouter: error getting shared key")
		return
	}

	n := max(len(r.listeners), len(r.cfg.Options.TailscaleListeners.Value))
	for i := range n {
		nl := &tsListener{
			ServerAddr:   r.cfg.Options.Addr,
			OutboundPort: r.cfg.OutboundPort,
			SignedJWTKey: sharedKey,
			Settings:     r.cfg.Options.TailscaleListeners.Value[i],
		}
		if i >= len(r.listeners) {
			r.listeners = append(r.listeners, nl)
			nl.Start(r.runCtx)
		} else if i >= len(r.cfg.Options.TailscaleListeners.Value) {
			r.listeners[i].Stop()
			r.listeners[i] = nil
		} else if !r.listeners[i].Equal(nl) {
			r.listeners[i].Stop()
			r.listeners[i] = nl
			nl.Start(r.runCtx)
		}
	}
	r.listeners = slices.DeleteFunc(r.listeners, func(l *tsListener) bool { return l == nil })
}
