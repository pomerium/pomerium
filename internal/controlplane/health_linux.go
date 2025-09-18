//go:build linux

package controlplane

import (
	"context"
	"os"
	"strconv"
	"time"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/health"
)

func (srv *Server) configureExtraProviders(
	ctx context.Context,
	cfg *config.Config,
	mgr health.ProviderManager,
	checks []health.Check,
) {
	srv.configureSdNotify(ctx, cfg, mgr, checks)
}

func (srv *Server) configureSdNotify(
	ctx context.Context,
	cfg *config.Config,
	mgr health.ProviderManager,
	checks []health.Check,
) {
	// if it already exists stop it
	existing := srv.SystemdProvider.Load()
	if existing != nil {
		existing.Shutdown()
	}
	srv.SystemdProvider.Store(nil)
	mgr.Deregister(health.ProviderSystemd)
	// https: //www.freedesktop.org/software/systemd/man/latest/sd_notify.html#Notes
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		log.Info().Msg("sd_notify notifications disabled, no socket available")
		return
	}
	if cfg.Options.HealthCheckSystemdDisabled {
		log.Info().Msg("sd_notify_notifications disabled")
		return
	}
	log.Info().Str("sock-addr", sock).Msg("sd_notify notifications enabled")
	enabled, dur := srv.watchdogEnabled()
	wconf := health.SystemdWatchdogConf{
		Enabled:  enabled,
		Interval: dur,
	}
	provider, err := health.NewSystemDProvider(ctx, mgr, sock, wconf, health.WithExpectedChecks(checks...))
	if err != nil {
		log.Error().Msg("failed to start sd_notify health checks")
		srv.SystemdProvider.Store(nil)
		return
	}
	log.Info().Bool("watchdog", enabled).Float64("intervalSeconds", wconf.Interval.Seconds()).Msg("started sd_notify health checks")
	mgr.Register(health.ProviderSystemd, provider)
	provider.Start()
	srv.SystemdProvider.Store(provider)
}

func (srv *Server) watchdogEnabled() (enabled bool, interval time.Duration) {
	// https://www.freedesktop.org/software/systemd/man/latest/sd_watchdog_enabled.html#Environment
	wusec := os.Getenv("WATCHDOG_USEC")
	wpid := os.Getenv("WATCHDOG_PID")

	if wusec == "" || wpid == "" {
		return false, 0
	}

	durMicroSeconds, err := strconv.Atoi(wusec)
	if err != nil {
		return false, 0
	}
	p, err := strconv.Atoi(wpid)
	if err != nil {
		return false, 0
	}

	if os.Getpid() != p {
		return false, 0
	}
	return true, time.Duration(durMicroSeconds) * time.Microsecond
}
