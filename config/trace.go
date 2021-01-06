package config

import (
	"fmt"
	"reflect"
	"sync"

	octrace "go.opencensus.io/trace"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
)

// TracingOptions are the options for tracing.
type TracingOptions = trace.TracingOptions

// NewTracingOptions builds a new TracingOptions from core Options
func NewTracingOptions(o *Options) (*TracingOptions, error) {
	tracingOpts := TracingOptions{
		Provider:            o.TracingProvider,
		Service:             telemetry.ServiceName(o.Services),
		JaegerAgentEndpoint: o.TracingJaegerAgentEndpoint,
		SampleRate:          o.TracingSampleRate,
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
	exporter  octrace.Exporter
}

// NewTraceManager creates a new TraceManager.
func NewTraceManager(src Source) *TraceManager {
	mgr := &TraceManager{}
	src.OnConfigChange(mgr.OnConfigChange)
	mgr.OnConfigChange(src.GetConfig())
	return mgr
}

// Close closes any underlying trace exporter.
func (mgr *TraceManager) Close() error {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	if mgr.exporter != nil {
		trace.UnregisterTracing(mgr.exporter)
	}
	return nil
}

// OnConfigChange updates the manager whenever the configuration is changed.
func (mgr *TraceManager) OnConfigChange(cfg *Config) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	traceOpts, err := NewTracingOptions(cfg.Options)
	if err != nil {
		log.Error().Err(err).Msg("trace: failed to build tracing options")
		return
	}

	if reflect.DeepEqual(traceOpts, mgr.traceOpts) {
		log.Debug().Msg("no change detected in trace options")
		return
	}
	mgr.traceOpts = traceOpts

	if mgr.exporter != nil {
		trace.UnregisterTracing(mgr.exporter)
		mgr.exporter = nil
	}

	if !traceOpts.Enabled() {
		return
	}

	log.Info().Interface("options", traceOpts).Msg("trace: starting exporter")

	mgr.exporter, err = trace.RegisterTracing(traceOpts)
	if err != nil {
		log.Error().Err(err).Msg("trace: failed to register exporter")
		return
	}
}
