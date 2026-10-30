package pomerium

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
	"github.com/pomerium/pomerium/pkg/health/v2/sink"
)

const healthGRPCBatchWindow = 15 * time.Second

func newHealthGRPCSink(src config.Source) *sink.GRPC {
	return sink.NewGRPC(healthGRPCBatchWindow, func() []byte {
		key, err := src.GetConfig().Options.GetSharedKey()
		if err != nil {
			log.Error().Err(err).Msg("health stream: failed to load shared key")
		}
		return key
	})
}

type healthSetup struct {
	src       config.Source
	startTime time.Time
	checkers  []healthv2.ServiceEvaluator
	sinks     []healthv2.HealthSink
}

// runHealth registers every checker and sink before it starts the manager.
// Sinks are shut down when ctx is done.
// The manager keeps running so it can monitor graceful shutdown.
func (p *Pomerium) runHealth(ctx context.Context, h healthSetup) error {
	mgr := p.healthMgr
	for _, c := range h.checkers {
		mgr.RegisterHealthChecker(c)
	}

	metricsSink, err := sink.NewMetrics(otel.Meter("health"), h.startTime)
	if err != nil {
		return err
	}
	sinks := append([]healthv2.HealthSink{metricsSink}, h.sinks...)
	if s := newSystemdSink(ctx, mgr, h.src); s != nil {
		sinks = append(sinks, s)
	}
	for _, s := range sinks {
		mgr.RegisterSink(s)
		context.AfterFunc(ctx, func() { s.Shutdown(ctx) })
	}

	go mgr.Run(ctx)
	return nil
}

func newSystemdSink(ctx context.Context, mgr *healthv2.Manager, src config.Source) *sink.Systemd {
	opts, ok := systemdOptions()
	if !ok {
		log.Ctx(ctx).Info().Msg("sd_notify notifications disabled, no socket available")
		return nil
	}
	s, err := sink.NewSystemd(mgr, opts)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to start sd_notify health checks")
		return nil
	}
	log.Ctx(ctx).Info().
		Str("sock-addr", opts.Addr).
		Dur("watchdog-interval", opts.WatchdogInterval).
		Msg("sd_notify notifications enabled")
	s.SetEnabled(!src.GetConfig().Options.HealthCheckSystemdDisabled)
	src.OnConfigChange(ctx, func(_ context.Context, cfg *config.Config) {
		s.SetEnabled(!cfg.Options.HealthCheckSystemdDisabled)
	})
	return s
}
