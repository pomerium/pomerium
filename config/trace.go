package config

import (
	"context"
	"fmt"
	"reflect"
	"sync"

	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// TracingOptions are the options for tracing.
type TracingOptions = trace.TracingOptions

// NewTracingOptions builds a new TracingOptions from core Options
func NewTracingOptions(o *Options) (*TracingOptions, error) {
	sampleRate := 1.0
	if o.TracingSampleRate != nil {
		sampleRate = *o.TracingSampleRate
	}
	tracingOpts := TracingOptions{
		Provider:            o.TracingProvider,
		Service:             telemetry.ServiceName(o.Services),
		JaegerAgentEndpoint: o.TracingJaegerAgentEndpoint,
		SampleRate:          sampleRate,
	}

	switch o.TracingProvider {
	case trace.DatadogTracingProviderName:
		tracingOpts.DatadogAddress = o.TracingDatadogAddress
	case trace.JaegerTracingProviderName:
		if o.TracingJaegerCollectorEndpoint != "" {
			jaegerCollectorEndpoint, err := urlutil.ParseAndValidateURL(o.TracingJaegerCollectorEndpoint)
			if err != nil {
				return nil, fmt.Errorf("config: invalid jaeger endpoint url: %w", err)
			}
			tracingOpts.JaegerCollectorEndpoint = jaegerCollectorEndpoint
			tracingOpts.JaegerAgentEndpoint = o.TracingJaegerAgentEndpoint
		}
	case trace.ZipkinTracingProviderName:
		zipkinEndpoint, err := urlutil.ParseAndValidateURL(o.ZipkinEndpoint)
		if err != nil {
			return nil, fmt.Errorf("config: invalid zipkin endpoint url: %w", err)
		}
		tracingOpts.ZipkinEndpoint = zipkinEndpoint
	case "":
		return &TracingOptions{}, nil
	default:
		return nil, fmt.Errorf("config: provider %s unknown", o.TracingProvider)
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

	traceOpts, err := NewTracingOptions(cfg.Options)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("trace: failed to build tracing options")
		return
	}

	if reflect.DeepEqual(traceOpts, mgr.traceOpts) {
		log.Ctx(ctx).Debug().Msg("no change detected in trace options")
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

	log.Ctx(ctx).Info().Interface("options", traceOpts).Msg("trace: starting exporter")

	mgr.provider, err = trace.GetProvider(traceOpts)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("trace: failed to register exporter")
		return
	}

	err = mgr.provider.Register(traceOpts)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("trace: failed to register exporter")
		return
	}
}
