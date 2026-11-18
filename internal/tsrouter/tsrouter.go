package tsrouter

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/rs/zerolog"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/pkg/grpc"
)

// A TSRouter routes traffic from tailscale to Pomerium.
type TSRouter interface {
	OnConfigChange(cfg *config.Config)
	Run(ctx context.Context) error
}

type tsRouter struct {
	telemetry      telemetry.Component
	databrokerConn grpc.CachedOutboundGRPClientConn
	tsRouterConfig *tsRouterConfig

	mu        sync.Mutex
	runCtx    context.Context
	cfg       *config.Config
	listeners []*tsListener
}

func New(tracerProvider oteltrace.TracerProvider, options ...Option) TSRouter {
	return &tsRouter{
		telemetry:      *telemetry.NewComponent(tracerProvider, zerolog.DebugLevel, "tsrouter"),
		databrokerConn: grpc.CachedOutboundGRPClientConn{Name: "tsrouter"},
		tsRouterConfig: getTSRouterConfig(options...),
	}
}

func (r *tsRouter) OnConfigChange(cfg *config.Config) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.cfg = cfg
	r.updateLocked()
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

	// Run only exits once ctx is done, which is a normal shutdown.
	return nil
}

func (r *tsRouter) updateLocked() {
	// tailscale routing is disabled, stop any listeners and return
	if r.cfg == nil || r.runCtx == nil ||
		!r.cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagTailscale) {
		for _, li := range r.listeners {
			li.Stop()
		}
		r.listeners = nil
		return
	}

	// tailscale routing is enabled, start listeners
	_, op := r.telemetry.Start(r.runCtx, "update")
	defer op.Complete()

	sharedKey, err := r.cfg.Options.GetSharedKey()
	if err != nil {
		_ = op.Failure(fmt.Errorf("failed to get shared key: %w", err))
		return
	}

	cc, err := r.databrokerConn.Get(r.runCtx, &grpc.OutboundOptions{
		OutboundPort: r.cfg.OutboundPort,
		SignedJWTKey: sharedKey,
	})
	if err != nil {
		_ = op.Failure(fmt.Errorf("failed to get databroker client connection: %w", err))
		return
	}

	// start new or updated listeners
	for i, s := range r.cfg.Options.TailscaleListeners.Value {
		nl, err := newTSListener(r.telemetry.GetTracerProvider(), r.cfg, s, r.tsRouterConfig, cc)
		if err != nil {
			// stop the current listener
			r.listeners[i].Stop()
			r.listeners[i] = nil
			_ = op.Failure(fmt.Errorf("error constructing listener: %w", err))
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
