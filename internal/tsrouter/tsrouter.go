package tsrouter

import (
	"context"
	"crypto/tls"
	"fmt"
	"slices"
	"sync"

	"github.com/rs/zerolog"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
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
	listeners map[string]*tsListener // by hostname
}

// New creates a new TSRouter.
func New(tracerProvider oteltrace.TracerProvider, options ...Option) TSRouter {
	return &tsRouter{
		telemetry:      *telemetry.NewComponent(tracerProvider, zerolog.DebugLevel, "tsrouter"),
		databrokerConn: grpc.CachedOutboundGRPClientConn{Name: "tsrouter"},
		tsRouterConfig: getTSRouterConfig(options...),
		listeners:      make(map[string]*tsListener),
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
		clear(r.listeners)
		return
	}

	// tailscale routing is enabled, start listeners
	ctx, op := r.telemetry.Start(r.runCtx, "update")
	defer op.Complete()

	sharedKey, err := r.cfg.Options.GetSharedKey()
	if err != nil {
		_ = op.Failure(fmt.Errorf("failed to get shared key: %w", err))
		return
	}

	certificates, err := getCertificates(r.cfg)
	if err != nil {
		_ = op.Failure(fmt.Errorf("failed to get certificates: %w", err))
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

	newListeners := map[string]*tsListener{}
	for _, s := range r.cfg.Options.TailscaleListeners.Value {
		newListeners[s.Hostname.Value] = newTSListener(r.telemetry.GetTracerProvider(), r.cfg, s, r.tsRouterConfig, cc, certificates)
	}

	var wg sync.WaitGroup
	// stop listeners
	for h, l := range r.listeners {
		nl, ok := newListeners[h]
		if ok && l.Equal(nl) {
			l.certificates.Store(new(certificates))
			newListeners[h] = l
			continue
		}
		log.Ctx(ctx).Info().Str("hostname", l.Settings.Hostname.Value).Msg("stopping tailscale listener")
		wg.Go(l.Stop)
		delete(r.listeners, h)
	}
	wg.Wait()

	// start listeners
	for h, nl := range newListeners {
		_, ok := r.listeners[h]
		if ok {
			continue
		}
		log.Ctx(ctx).Info().Str("hostname", nl.Settings.Hostname.Value).Msg("starting tailscale listener")
		wg.Go(func() { nl.Start(ctx) })
	}
	wg.Wait()

	r.listeners = newListeners
}

func getCertificates(cfg *config.Config) ([]tls.Certificate, error) {
	certs, err := cfg.AllCertificates()
	if err != nil {
		return nil, fmt.Errorf("error loading certificates: %w", err)
	}
	catchAll, err := cfg.GenerateCatchAllCertificate()
	if err != nil {
		return nil, fmt.Errorf("error generating catch-all certificate: %w", err)
	}
	return append(slices.Clone(certs), *catchAll), nil
}
