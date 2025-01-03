package trace

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	v1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

var (
	ErrNoClient      = errors.New("no client")
	ErrClientStopped = errors.New("client is stopped")
)

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
	mu               sync.Mutex
	client           otlptrace.Client
	waitForNewClient chan struct{}
}

var _ SyncClient = (*syncClient)(nil)

// Start implements otlptrace.Client.
func (ac *syncClient) Start(ctx context.Context) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if ac.waitForNewClient != nil {
		panic("bug: Start called during Stop or Update")
	}
	if ac.client == nil {
		return ErrNoClient
	}
	return ac.client.Start(ctx)
}

// Stop implements otlptrace.Client.
func (ac *syncClient) Stop(ctx context.Context) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if ac.waitForNewClient != nil {
		panic("bug: Stop called concurrently")
	}
	return ac.resetLocked(ctx, nil)
}

func (ac *syncClient) resetLocked(ctx context.Context, newClient otlptrace.Client) error {
	if ac.client == nil {
		return ErrNoClient
	}
	ac.waitForNewClient = make(chan struct{})
	ac.mu.Unlock()

	err := ac.client.Stop(ctx)

	ac.mu.Lock()
	close(ac.waitForNewClient)
	ac.waitForNewClient = nil
	ac.client = newClient
	return err
}

// UploadTraces implements otlptrace.Client.
func (ac *syncClient) UploadTraces(ctx context.Context, protoSpans []*v1.ResourceSpans) error {
	ac.mu.Lock()
	if ac.waitForNewClient != nil {
		wait := ac.waitForNewClient
		ac.mu.Unlock()
		select {
		case <-wait:
			ac.mu.Lock()
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	} else if ac.client == nil {
		ac.mu.Unlock()
		return ErrNoClient
	}
	client := ac.client
	ac.mu.Unlock()
	if client == nil {
		return ErrClientStopped
	}
	return client.UploadTraces(ctx, protoSpans)
}

func (ac *syncClient) Update(ctx context.Context, newClient otlptrace.Client) error {
	if newClient != nil {
		if err := newClient.Start(ctx); err != nil {
			return fmt.Errorf("error starting new client: %w", err)
		}
	}
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if ac.waitForNewClient != nil {
		panic("bug: Update called during Stop")
	}
	if newClient == ac.client {
		return nil
	}
	return ac.resetLocked(ctx, newClient)
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
			var specific bool
			if v, ok := os.LookupEnv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"); ok {
				endpoint = v
				specific = true
			} else if v, ok := os.LookupEnv("OTEL_EXPORTER_OTLP_ENDPOINT"); ok {
				endpoint = v
			}
			protocol = BestEffortProtocolFromOTLPEndpoint(endpoint, specific)
		}
		switch strings.ToLower(strings.TrimSpace(protocol)) {
		case "grpc":
			return otlptracegrpc.NewClient()
		case "http/protobuf", "":
			return otlptracehttp.NewClient()
		default:
			otel.Handle(fmt.Errorf(`unknown otlp trace exporter protocol %q, expected "grpc" or "http/protobuf"`, protocol))
			return NoopClient{}
		}
	default:
		otel.Handle(fmt.Errorf(`unknown otlp trace exporter %q, expected "otlp" or "none"`, exporter))
		return NoopClient{}
	}
}

func BestEffortProtocolFromOTLPEndpoint(endpoint string, specificEnv bool) string {
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
		// For http, if the signal-specific form of the endpoint env variable
		// (e.g. $OTEL_EXPORTER_OTLP_TRACES_ENDPOINT) is used, the /v1/<signal>
		//                           ^^^^^^
		// path must be present. Otherwise, the path must _not_ be present,
		// because the sdk will add it.
		// This doesn't apply to grpc endpoints, so assume grpc if there is a
		// conflict here.
		hasPath := len(strings.Trim(u.Path, "/")) > 0
		switch {
		case hasPath && specificEnv:
			return "http/protobuf"
		case !hasPath && specificEnv:
			return "grpc"
		case hasPath && !specificEnv:
			// would be invalid for http, so assume it's grpc on a subpath
			return "grpc"
		case !hasPath && !specificEnv:
			// could be either, but default to http
			return "http/protobuf"
		}
		panic("unreachable")
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
