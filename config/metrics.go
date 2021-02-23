package config

import (
	"net/http"
	"sync"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
)

// A MetricsManager manages metrics for a given configuration.
type MetricsManager struct {
	mu          sync.Mutex
	serviceName string
	addr        string
	basicAuth   string
	srv         *http.Server
}

// NewMetricsManager creates a new MetricsManager.
func NewMetricsManager(src Source) *MetricsManager {
	mgr := &MetricsManager{}
	metrics.RegisterInfoMetrics()
	src.OnConfigChange(mgr.OnConfigChange)
	mgr.OnConfigChange(src.GetConfig())
	return mgr
}

// Close closes any underlying http server.
func (mgr *MetricsManager) Close() error {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	var err error
	if mgr.srv != nil {
		err = mgr.srv.Close()
		mgr.srv = nil
	}
	return err
}

// OnConfigChange updates the metrics manager when configuration is changed.
func (mgr *MetricsManager) OnConfigChange(cfg *Config) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	mgr.updateInfo(cfg)
	mgr.updateServer(cfg)
}

func (mgr *MetricsManager) updateInfo(cfg *Config) {
	serviceName := telemetry.ServiceName(cfg.Options.Services)
	if serviceName == mgr.serviceName {
		return
	}

	metrics.SetBuildInfo(serviceName)
	mgr.serviceName = serviceName
}

func (mgr *MetricsManager) updateServer(cfg *Config) {
	if cfg.Options.MetricsAddr == mgr.addr && cfg.Options.MetricsBasicAuth == mgr.basicAuth {
		return
	}

	if mgr.srv != nil {
		err := mgr.srv.Close()
		if err != nil {
			log.Warn().Err(err).Msg("metrics: error closing http server")
		}
		mgr.srv = nil
	}

	mgr.addr = cfg.Options.MetricsAddr
	mgr.basicAuth = cfg.Options.MetricsBasicAuth
	if mgr.addr == "" {
		log.Info().Msg("metrics: http server disabled")
		return
	}

	log.Info().Str("addr", mgr.addr).Msg("metrics: starting http server")

	handler, err := metrics.PrometheusHandler(EnvoyAdminURL)
	if err != nil {
		log.Error().Err(err).Msg("metrics: failed to create prometheus handler")
		return
	}

	if username, password, ok := cfg.Options.GetMetricsBasicAuth(); ok {
		handler = middleware.RequireBasicAuth(username, password)(handler)
	}

	mgr.srv, err = httputil.NewServer(&httputil.ServerOptions{
		Addr:     mgr.addr,
		Insecure: true,
		Service:  "metrics",
	}, handler, new(sync.WaitGroup))
	if err != nil {
		log.Error().Err(err).Msg("metrics: failed to create metrics http server")
		return
	}
}
