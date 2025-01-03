package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
)

var ErrNoTracingConfig = errors.New("no tracing config")

func NewTraceClientFromOptions(opts *Options) (otlptrace.Client, error) {
	switch opts.TracingProvider {
	case "otlp":
		endpoint := opts.TracingOTLPEndpoint
		protocol := opts.TracingOTLPProtocol
		if protocol == "" && endpoint != "" {
			// treat this field as equivalent to OTEL_EXPORTER_OTLP_TRACES_ENDPOINT
			protocol = trace.BestEffortProtocolFromOTLPEndpoint(opts.TracingOTLPEndpoint, true)
		}
		switch strings.ToLower(strings.TrimSpace(protocol)) {
		case "grpc":
			return otlptracegrpc.NewClient(
				otlptracegrpc.WithEndpointURL(endpoint),
			), nil
		case "http/protobuf", "":
			return otlptracehttp.NewClient(
				otlptracehttp.WithEndpointURL(endpoint),
			), nil
		default:
			return nil, fmt.Errorf(`unknown otlp trace exporter protocol %q, expected "grpc" or "http/protobuf"\n`, protocol)
		}
	case "none", "noop":
		return trace.NoopClient{}, nil
	case "":
		return nil, ErrNoTracingConfig
	default:
		return nil, fmt.Errorf(`unknown tracing provider %q, expected one of ["otlp"]`, opts.TracingProvider)
	}
}
