package trace

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	v1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

func NewRemoteClientFromEnv() otlptrace.Client {
	exporter, ok := os.LookupEnv("OTEL_TRACES_EXPORTER")
	if !ok {
		exporter = "none"
	}

	switch strings.ToLower(strings.TrimSpace(exporter)) {
	case "none", "noop", "":
		return noopClient{}
	case "otlp":
		var protocol string
		if v, ok := os.LookupEnv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"); ok {
			protocol = v
		} else if v, ok := os.LookupEnv("OTEL_EXPORTER_OTLP_PROTOCOL"); ok {
			protocol = v
		} else {
			// try to guess the expected protocol from the port number
			protocol = guessProtocol()
		}
		switch strings.ToLower(strings.TrimSpace(protocol)) {
		case "grpc":
			return otlptracegrpc.NewClient()
		case "http/protobuf", "":
			return otlptracehttp.NewClient()
		default:
			fmt.Fprintf(os.Stderr, `unknown otlp trace exporter protocol %q, expected "grpc" or "http/protobuf"\n`, protocol)
			return noopClient{}
		}
	default:
		fmt.Fprintf(os.Stderr, `unknown otlp trace exporter %q, expected "otlp" or "none"\n`, exporter)
		return noopClient{}
	}
}

func guessProtocol() string {
	var endpoint string
	if v, ok := os.LookupEnv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"); ok {
		endpoint = v
	} else if v, ok := os.LookupEnv("OTEL_EXPORTER_OTLP_ENDPOINT"); ok {
		endpoint = v
	}
	if endpoint == "" {
		return ""
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	switch u.Port() {
	case "4318":
		return "http/protobuf"
	case "4317":
		return "grpc"
	default:
		if len(strings.Trim(u.Path, "/")) > 0 {
			return "http/protobuf"
		}
		return "grpc"
	}
}

type noopClient struct{}

// Start implements otlptrace.Client.
func (n noopClient) Start(ctx context.Context) error {
	return nil
}

// Stop implements otlptrace.Client.
func (n noopClient) Stop(ctx context.Context) error {
	return nil
}

// UploadTraces implements otlptrace.Client.
func (n noopClient) UploadTraces(ctx context.Context, protoSpans []*v1.ResourceSpans) error {
	return nil
}
