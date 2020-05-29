package config

import (
	"fmt"
	"net/url"

	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/urlutil"
)

const (
	// JaegerTracingProviderName is the name of the tracing provider Jaeger.
	JaegerTracingProviderName = "jaeger"
	// ZipkinTracingProviderName is the name of the tracing provider Zipkin.
	ZipkinTracingProviderName = "zipkin"
)

// TracingOptions contains the configurations settings for a http server.
type TracingOptions struct {
	// Shared
	Provider string
	Service  string
	Debug    bool

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

// NewTracingOptions builds a new TracingOptions from core Options
func NewTracingOptions(o *Options) (*TracingOptions, error) {
	tracingOpts := TracingOptions{
		Provider:            o.TracingProvider,
		Service:             telemetry.ServiceName(o.Services),
		JaegerAgentEndpoint: o.TracingJaegerAgentEndpoint,
		SampleRate:          o.TracingSampleRate,
	}

	switch o.TracingProvider {
	case JaegerTracingProviderName:
		if o.TracingJaegerCollectorEndpoint != "" {
			jaegerCollectorEndpoint, err := urlutil.ParseAndValidateURL(o.TracingJaegerCollectorEndpoint)
			if err != nil {
				return nil, fmt.Errorf("config: invalid jaeger endpoint url: %w", err)
			}
			tracingOpts.JaegerCollectorEndpoint = jaegerCollectorEndpoint
			tracingOpts.JaegerAgentEndpoint = o.TracingJaegerAgentEndpoint
		}
	case ZipkinTracingProviderName:
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

// Enabled indicates whether tracing is enabled on a given TracingOptions
func (t *TracingOptions) Enabled() bool {
	return t.Provider != ""
}
