package trace

import (
	"context"
	"fmt"

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
	JaegerCollectorEndpoint string `mapstructure:"tracing_jaeger_collector_endpoint"`
	// AgentEndpoint instructs exporter to send spans to jaeger-agent at this address.
	// For example, localhost:6831.
	JaegerAgentEndpoint string `mapstructure:"tracing_jaeger_agent_endpoint"`

	// Zipkin

	// ZipkinEndpoint configures the zipkin collector URI
	// Example: http://zipkin:9411/api/v2/spans
	ZipkinEndpoint string `mapstructure:"tracing_zipkin_endpoint"`
}

// RegisterTracing creates a new trace exporter from TracingOptions.
func RegisterTracing(opts *TracingOptions) error {
	var err error
	switch opts.Provider {
	case JaegerTracingProviderName:
		err = registerJaeger(opts)
	case ZipkinTracingProviderName:
		err = registerZipkin(opts)
	default:
		return fmt.Errorf("telemetry/trace: provider %s unknown", opts.Provider)
	}
	if err != nil {
		return err
	}
	if opts.Debug {
		log.Debug().Msg("telemetry/trace: debug on, sample everything")
		trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})
	}
	log.Debug().Interface("Opts", opts).Msg("telemetry/trace: exporter created")
	return nil
}

func registerJaeger(opts *TracingOptions) error {
	jex, err := jaeger.NewExporter(
		jaeger.Options{
			AgentEndpoint:     opts.JaegerAgentEndpoint,
			CollectorEndpoint: opts.JaegerCollectorEndpoint,
			ServiceName:       opts.Service,
		})
	if err != nil {
		return err
	}
	trace.RegisterExporter(jex)
	return nil
}

func registerZipkin(opts *TracingOptions) error {
	localEndpoint, err := zipkin.NewEndpoint(opts.Service, "")
	if err != nil {
		return fmt.Errorf("telemetry/trace: could not create local endpoint: %w", err)
	}

	reporter := zipkinHTTP.NewReporter(opts.ZipkinEndpoint)

	exporter := ocZipkin.NewExporter(reporter, localEndpoint)
	trace.RegisterExporter(exporter)

	return nil
}

// StartSpan starts a new child span of the current span in the context. If
// there is no span in the context, creates a new trace and span.
//
// Returned context contains the newly created span. You can use it to
// propagate the returned span in process.
func StartSpan(ctx context.Context, name string, o ...trace.StartOption) (context.Context, *trace.Span) {
	return trace.StartSpan(ctx, name, o...)
}
