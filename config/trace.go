package config

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"

	"github.com/rs/zerolog"
)

// TracingOptions are the options for tracing.
type TracingOptions = trace.TracingOptions

// NewTracingOptions builds a new TracingOptions from core Options
func NewTracingOptions(cfg *Config) (*TracingOptions, error) {
	tracingOpts := TracingOptions{
		Provider:            cfg.Options.TracingProvider,
		Service:             telemetry.ServiceName(cfg.Options.Services),
		JaegerAgentEndpoint: cfg.Options.TracingJaegerAgentEndpoint,
		SampleRate:          cfg.Options.TracingSampleRate,
	}

	switch cfg.Options.TracingProvider {
	case trace.DatadogTracingProviderName:
		tracingOpts.DatadogAddress = cfg.Options.TracingDatadogAddress
	case trace.JaegerTracingProviderName:
		if cfg.Options.TracingJaegerCollectorEndpoint != "" {
			jaegerCollectorEndpoint, err := urlutil.ParseAndValidateURL(cfg.Options.TracingJaegerCollectorEndpoint)
			if err != nil {
				return nil, fmt.Errorf("config: invalid jaeger endpoint url: %w", err)
			}
			tracingOpts.JaegerCollectorEndpoint = jaegerCollectorEndpoint
			tracingOpts.JaegerAgentEndpoint = cfg.Options.TracingJaegerAgentEndpoint
		}
	case trace.ZipkinTracingProviderName:
		zipkinEndpoint, err := urlutil.ParseAndValidateURL(cfg.Options.ZipkinEndpoint)
		if err != nil {
			return nil, fmt.Errorf("config: invalid zipkin endpoint url: %w", err)
		}
		tracingOpts.ZipkinEndpoint = zipkinEndpoint
	case "":
		return &TracingOptions{}, nil
	default:
		return nil, fmt.Errorf("config: provider %s unknown", cfg.Options.TracingProvider)
	}

	return &tracingOpts, nil
}

// A TraceManager manages setting up a trace exporter based on configuration options.
type TraceManager struct {
	mu        sync.Mutex
	traceOpts *TracingOptions
	provider  trace.Provider
}

// NewTraceManager creates a new TraceManager.
func NewTraceManager(ctx context.Context, src Source) *TraceManager {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "trace_manager")
	})
	mgr := &TraceManager{}
	src.OnConfigChange(ctx, mgr.OnConfigChange)
	mgr.OnConfigChange(ctx, src.GetConfig())
	return mgr
}

// Close closes any underlying trace exporter.
func (mgr *TraceManager) Close() error {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	var err error
	if mgr.provider != nil {
		err = mgr.provider.Unregister()
	}
	return err
}

// OnConfigChange updates the manager whenever the configuration is changed.
func (mgr *TraceManager) OnConfigChange(ctx context.Context, cfg *Config) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	traceOpts, err := NewTracingOptions(cfg)
	if err != nil {
		log.Error(ctx).Err(err).Msg("trace: failed to build tracing options")
		return
	}

	if reflect.DeepEqual(traceOpts, mgr.traceOpts) {
		log.Debug(ctx).Msg("no change detected in trace options")
		return
	}
	mgr.traceOpts = traceOpts

	if mgr.provider != nil {
		_ = mgr.provider.Unregister()
		mgr.provider = nil
	}

	if !traceOpts.Enabled() {
		return
	}

	log.Info(ctx).Interface("options", traceOpts).Msg("trace: starting exporter")

	mgr.provider, err = trace.GetProvider(traceOpts)
	if err != nil {
		log.Error(ctx).Err(err).Msg("trace: failed to register exporter")
		return
	}

	err = mgr.provider.Register(traceOpts)
	if err != nil {
		log.Error(ctx).Err(err).Msg("trace: failed to register exporter")
		return
	}
}
