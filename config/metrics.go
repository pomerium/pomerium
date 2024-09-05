package config

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
)

const (
	// defaultMetricsTimeout sets max time to collect and send aggregate pomerium metrics
	defaultMetricsTimeout = time.Second * 30
)

// A MetricsManager manages metrics for a given configuration.
type MetricsManager struct {
	mu             sync.RWMutex
	installationID string
	serviceName    string
	addr           string
	basicAuth      string
	handler        http.Handler
	endpoints      []MetricsScrapeEndpoint
}

// NewMetricsManager creates a new MetricsManager.
func NewMetricsManager(ctx context.Context, src Source) *MetricsManager {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "metrics_manager")
	})
	mgr := &MetricsManager{}
	metrics.RegisterInfoMetrics()
	src.OnConfigChange(ctx, mgr.OnConfigChange)
	mgr.OnConfigChange(ctx, src.GetConfig())
	return mgr
}

// Close closes any underlying http server.
func (mgr *MetricsManager) Close() error {
	return nil
}

// OnConfigChange updates the metrics manager when configuration is changed.
func (mgr *MetricsManager) OnConfigChange(ctx context.Context, cfg *Config) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	mgr.updateInfo(ctx, cfg)
	mgr.updateServer(ctx, cfg)
}

func (mgr *MetricsManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()

	if mgr.handler == nil {
		http.NotFound(w, r)
		return
	}
	mgr.handler.ServeHTTP(w, r)
}

func (mgr *MetricsManager) updateInfo(ctx context.Context, cfg *Config) {
	serviceName := telemetry.ServiceName(cfg.Options.Services)
	if serviceName == mgr.serviceName {
		return
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("telemetry/metrics: failed to get OS hostname")
		hostname = "__unknown__"
	}

	metrics.SetBuildInfo(serviceName, hostname, cfg.EnvoyVersion)
	mgr.serviceName = serviceName
}

func (mgr *MetricsManager) updateServer(ctx context.Context, cfg *Config) {
	if mgr.configUnchanged(cfg) {
		return
	}

	mgr.addr = cfg.Options.MetricsAddr
	mgr.basicAuth = cfg.Options.MetricsBasicAuth
	mgr.installationID = cfg.Options.InstallationID
	mgr.handler = nil

	if mgr.addr == "" {
		log.Info(ctx).Msg("metrics: http server disabled")
		return
	}

	mgr.endpoints = append(cfg.MetricsScrapeEndpoints,
		MetricsScrapeEndpoint{
			Name: "envoy",
			URL:  url.URL{Scheme: "http", Host: cfg.Options.MetricsAddr, Path: "/metrics/envoy"},
		})
	handler, err := metrics.PrometheusHandler(toInternalEndpoints(mgr.endpoints), mgr.installationID, defaultMetricsTimeout)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("metrics: failed to create prometheus handler")
		return
	}

	if username, password, ok := cfg.Options.GetMetricsBasicAuth(); ok {
		handler = middleware.RequireBasicAuth(username, password)(handler)
	}

	mgr.handler = handler
}

func (mgr *MetricsManager) configUnchanged(cfg *Config) bool {
	return cfg.Options.MetricsAddr == mgr.addr &&
		cfg.Options.MetricsBasicAuth == mgr.basicAuth &&
		cfg.Options.InstallationID == mgr.installationID &&
		reflect.DeepEqual(mgr.endpoints, cfg.MetricsScrapeEndpoints)
}

func toInternalEndpoints(src []MetricsScrapeEndpoint) []metrics.ScrapeEndpoint {
	dst := make([]metrics.ScrapeEndpoint, 0, len(src))
	for _, e := range src {
		dst = append(dst, metrics.ScrapeEndpoint(e))
	}
	return dst
}
