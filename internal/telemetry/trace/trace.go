package trace

import (
	"context"
	"fmt"
	"net/url"

	octrace "go.opencensus.io/trace"

	"github.com/pomerium/pomerium/internal/log"
)

const (
	// DatadogTracingProviderName is the name of the tracing provider Datadog.
	DatadogTracingProviderName = "datadog"
	// JaegerTracingProviderName is the name of the tracing provider Jaeger.
	JaegerTracingProviderName = "jaeger"
	// ZipkinTracingProviderName is the name of the tracing provider Zipkin.
	ZipkinTracingProviderName = "zipkin"
)

// Provider is a trace provider.
type Provider interface {
	Register(options *TracingOptions) error
	Unregister() error
}

// TracingOptions contains the configurations settings for a http server.
type TracingOptions struct {
	// Shared
	Provider string
	Service  string
	Debug    bool

	// Datadog
	DatadogAddress string

	// Jaeger

	// CollectorEndpoint is the full url to the Jaeger HTTP Thrift collector.
	// For example, http://localhost:14268/api/traces
	JaegerCollectorEndpoint *url.URL
	// AgentEndpoint instructs exporter to send spans to jaeger-agent at this address.
	// For example, localhost:6831.
	JaegerAgentEndpoint string

	// Zipkin

	// ZipkinEndpoint configures the zipkin collector URI
	// Example: http://zipkin:9411/api/v2/spans
	ZipkinEndpoint *url.URL

	// SampleRate is percentage of requests which are sampled
	SampleRate float64
}

// Enabled indicates whether tracing is enabled on a given TracingOptions
func (t *TracingOptions) Enabled() bool {
	return t.Provider != ""
}

// GetProvider creates a new trace provider from TracingOptions.
func GetProvider(opts *TracingOptions) (Provider, error) {
	var provider Provider
	switch opts.Provider {
	case DatadogTracingProviderName:
		provider = new(datadogProvider)
	case JaegerTracingProviderName:
		provider = new(jaegerProvider)
	case ZipkinTracingProviderName:
		provider = new(zipkinProvider)
	default:
		return nil, fmt.Errorf("telemetry/trace: provider %s unknown", opts.Provider)
	}
	octrace.ApplyConfig(octrace.Config{DefaultSampler: octrace.ProbabilitySampler(opts.SampleRate)})

	log.Debug().Interface("Opts", opts).Msg("telemetry/trace: provider created")
	return provider, nil
}

// StartSpan starts a new child span of the current span in the context. If
// there is no span in the context, creates a new trace and span.
//
// Returned context contains the newly created span. You can use it to
// propagate the returned span in process.
func StartSpan(ctx context.Context, name string, o ...octrace.StartOption) (context.Context, *octrace.Span) {
	return octrace.StartSpan(ctx, name, o...)
}
