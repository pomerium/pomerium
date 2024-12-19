package trace

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	v1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

var ErrNoClient = errors.New("no client")

type SyncClient interface {
	otlptrace.Client

	Update(ctx context.Context, newClient otlptrace.Client) error
}

func NewSyncClient(client otlptrace.Client) SyncClient {
	return &syncClient{
		client: client,
	}
}

type syncClient struct {
	mu     sync.Mutex
	client otlptrace.Client
}

var _ SyncClient = (*syncClient)(nil)

// Start implements otlptrace.Client.
func (ac *syncClient) Start(ctx context.Context) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if ac.client == nil {
		return ErrNoClient
	}
	return ac.client.Start(ctx)
}

// Stop implements otlptrace.Client.
func (ac *syncClient) Stop(ctx context.Context) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if ac.client == nil {
		return ErrNoClient
	}
	err := ac.client.Stop(ctx)
	ac.client = nil
	return err
}

// UploadTraces implements otlptrace.Client.
func (ac *syncClient) UploadTraces(ctx context.Context, protoSpans []*v1.ResourceSpans) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if ac.client == nil {
		return ErrNoClient
	}
	return ac.client.UploadTraces(ctx, protoSpans)
}

func (ac *syncClient) Update(ctx context.Context, newClient otlptrace.Client) error {
	ac.mu.Lock()
	if err := newClient.Start(ctx); err != nil {
		ac.mu.Unlock()
		return fmt.Errorf("error starting new client: %w", err)
	}
	oldClient := ac.client
	ac.client = newClient
	ac.mu.Unlock()

	if oldClient != nil {
		if err := oldClient.Stop(ctx); err != nil {
			return fmt.Errorf("stopping old client: %w", err)
		}
	}
	return nil
}

// NewRemoteClientFromEnv creates an otlp trace client using the well-known
// environment variables defined in the [OpenTelemetry documentation].
//
// [OpenTelemetry documentation]: https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/
func NewRemoteClientFromEnv() otlptrace.Client {
	if os.Getenv("OTEL_SDK_DISABLED") == "true" {
		return NoopClient{}
	}

	exporter, ok := os.LookupEnv("OTEL_TRACES_EXPORTER")
	if !ok {
		exporter = "none"
	}

	switch strings.ToLower(strings.TrimSpace(exporter)) {
	case "none", "noop", "":
		return NoopClient{}
	case "otlp":
		var protocol string
		if v, ok := os.LookupEnv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"); ok {
			protocol = v
		} else if v, ok := os.LookupEnv("OTEL_EXPORTER_OTLP_PROTOCOL"); ok {
			protocol = v
		} else {
			// try to guess the expected protocol from the port number
			var endpoint string
			if v, ok := os.LookupEnv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"); ok {
				endpoint = v
			} else if v, ok := os.LookupEnv("OTEL_EXPORTER_OTLP_ENDPOINT"); ok {
				endpoint = v
			}
			protocol = BestEffortProtocolFromOTLPEndpoint(endpoint)
		}
		switch strings.ToLower(strings.TrimSpace(protocol)) {
		case "grpc":
			return otlptracegrpc.NewClient()
		case "http/protobuf", "":
			return otlptracehttp.NewClient()
		default:
			fmt.Fprintf(os.Stderr, `unknown otlp trace exporter protocol %q, expected "grpc" or "http/protobuf"\n`, protocol)
			return NoopClient{}
		}
	default:
		fmt.Fprintf(os.Stderr, `unknown otlp trace exporter %q, expected "otlp" or "none"\n`, exporter)
		return NoopClient{}
	}
}

func BestEffortProtocolFromOTLPEndpoint(endpoint string) string {
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

type NoopClient struct{}

// Start implements otlptrace.Client.
func (n NoopClient) Start(context.Context) error {
	return nil
}

// Stop implements otlptrace.Client.
func (n NoopClient) Stop(context.Context) error {
	return nil
}

// UploadTraces implements otlptrace.Client.
func (n NoopClient) UploadTraces(context.Context, []*v1.ResourceSpans) error {
	return nil
}
