package trace

import (
	"context"
	"fmt"
	"net/url"

	"contrib.go.opencensus.io/exporter/jaeger"
	ocZipkin "contrib.go.opencensus.io/exporter/zipkin"
	"github.com/openzipkin/zipkin-go"
	zipkinHTTP "github.com/openzipkin/zipkin-go/reporter/http"
	"go.opencensus.io/trace"

	"github.com/pomerium/pomerium/internal/log"
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

// Enabled indicates whether tracing is enabled on a given TracingOptions
func (t *TracingOptions) Enabled() bool {
	return t.Provider != ""
}

// RegisterTracing creates a new trace exporter from TracingOptions.
func RegisterTracing(opts *TracingOptions) (trace.Exporter, error) {
	var exporter trace.Exporter
	var err error
	switch opts.Provider {
	case JaegerTracingProviderName:
		exporter, err = registerJaeger(opts)
	case ZipkinTracingProviderName:
		exporter, err = registerZipkin(opts)
	default:
		return nil, fmt.Errorf("telemetry/trace: provider %s unknown", opts.Provider)
	}
	if err != nil {
		return nil, err
	}
	trace.ApplyConfig(trace.Config{DefaultSampler: trace.ProbabilitySampler(opts.SampleRate)})

	log.Debug().Interface("Opts", opts).Msg("telemetry/trace: exporter created")
	return exporter, nil
}

// UnregisterTracing unregisters a trace exporter.
func UnregisterTracing(exporter trace.Exporter) {
	trace.UnregisterExporter(exporter)
}

func registerJaeger(opts *TracingOptions) (trace.Exporter, error) {
	jOpts := jaeger.Options{
		ServiceName:   opts.Service,
		AgentEndpoint: opts.JaegerAgentEndpoint,
	}
	if opts.JaegerCollectorEndpoint != nil {
		jOpts.CollectorEndpoint = opts.JaegerCollectorEndpoint.String()
	}
	jex, err := jaeger.NewExporter(jOpts)
	if err != nil {
		return nil, err
	}
	trace.RegisterExporter(jex)
	return jex, nil
}

func registerZipkin(opts *TracingOptions) (trace.Exporter, error) {
	localEndpoint, err := zipkin.NewEndpoint(opts.Service, "")
	if err != nil {
		return nil, fmt.Errorf("telemetry/trace: could not create local endpoint: %w", err)
	}

	reporter := zipkinHTTP.NewReporter(opts.ZipkinEndpoint.String())

	exporter := ocZipkin.NewExporter(reporter, localEndpoint)
	trace.RegisterExporter(exporter)

	return exporter, nil
}

// StartSpan starts a new child span of the current span in the context. If
// there is no span in the context, creates a new trace and span.
//
// Returned context contains the newly created span. You can use it to
// propagate the returned span in process.
func StartSpan(ctx context.Context, name string, o ...trace.StartOption) (context.Context, *trace.Span) {
	return trace.StartSpan(ctx, name, o...)
}
