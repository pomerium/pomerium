package trace

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pomerium/pomerium/config/otelconfig"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	v1 "go.opentelemetry.io/proto/otlp/trace/v1"
)

var (
	ErrNoClient      = errors.New("no client")
	ErrClientStopped = errors.New("client is stopped")
)

// SyncClient wraps an underlying [otlptrace.Client] which can be swapped out
// for a different client (e.g. in response to a config update) safely and in
// a way that does not lose spans.
type SyncClient interface {
	otlptrace.Client

	// Update safely replaces the current trace client with the one provided.
	// The new client must be unstarted. The old client (if any) will be stopped.
	//
	// This function is NOT reentrant; callers must use appropriate locking.
	Update(ctx context.Context, newClient otlptrace.Client) error
}

// NewSyncClient creates a new [SyncClient] with an initial underlying client.
//
// The client can be nil; if so, calling any method on the SyncClient will
// return ErrNoClient.
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
	if ac.client == nil {
		return ErrNoClient
	}
	return ac.resetLocked(ctx, nil)
}

func (ac *syncClient) resetLocked(ctx context.Context, newClient otlptrace.Client) error {
	var stop func(context.Context) error
	if ac.client != nil {
		stop = ac.client.Stop
	}
	ac.waitForNewClient = make(chan struct{})
	ac.mu.Unlock()

	var err error
	if stop != nil {
		err = stop(ctx)
	}

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

func NewTraceClientFromConfig(opts otelconfig.Config) (otlptrace.Client, error) {
	if IsOtelSDKDisabled() {
		return NoopClient{}, nil
	}
	if opts.OtelTracesExporter == nil {
		return NoopClient{}, nil
	}
	switch *opts.OtelTracesExporter {
	case "otlp":
		var endpoint, protocol string
		var signalSpecificEndpoint bool

		if opts.OtelExporterOtlpTracesEndpoint != nil {
			endpoint = *opts.OtelExporterOtlpTracesEndpoint
			signalSpecificEndpoint = true
		} else if opts.OtelExporterOtlpEndpoint != nil {
			endpoint = *opts.OtelExporterOtlpEndpoint
			signalSpecificEndpoint = false
		}
		if opts.OtelExporterOtlpTracesProtocol != nil {
			protocol = *opts.OtelExporterOtlpTracesProtocol
		} else if opts.OtelExporterOtlpProtocol != nil {
			protocol = *opts.OtelExporterOtlpProtocol
		}

		if protocol == "" {
			protocol = BestEffortProtocolFromOTLPEndpoint(endpoint, signalSpecificEndpoint)
		}

		var headersList []string
		if len(opts.OtelExporterOtlpTracesHeaders) > 0 {
			headersList = opts.OtelExporterOtlpTracesHeaders
		} else if len(opts.OtelExporterOtlpHeaders) > 0 {
			headersList = opts.OtelExporterOtlpHeaders
		}
		headers := map[string]string{}
		for _, kv := range headersList {
			k, v, ok := strings.Cut(kv, "=")
			if ok {
				headers[k] = v
			}
		}
		defaultTimeout := 10 * time.Second // otel default (not exported)
		if opts.OtelExporterOtlpTimeout != nil {
			defaultTimeout = max(0, time.Duration(*opts.OtelExporterOtlpTimeout)*time.Millisecond)
		}
		switch strings.ToLower(strings.TrimSpace(protocol)) {
		case "grpc":
			return otlptracegrpc.NewClient(
				otlptracegrpc.WithEndpointURL(endpoint),
				otlptracegrpc.WithHeaders(headers),
				otlptracegrpc.WithTimeout(defaultTimeout),
			), nil
		case "http/protobuf", "":
			return otlptracehttp.NewClient(
				otlptracehttp.WithEndpointURL(endpoint),
				otlptracehttp.WithHeaders(headers),
				otlptracehttp.WithTimeout(defaultTimeout),
			), nil
		default:
			return nil, fmt.Errorf(`unknown otlp trace exporter protocol %q, expected one of ["grpc", "http/protobuf"]`, protocol)
		}
	case "none", "noop", "":
		return NoopClient{}, nil
	default:
		return nil, fmt.Errorf(`unknown otlp trace exporter %q, expected one of ["otlp", "none"]`, *opts.OtelTracesExporter)
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

// ValidNoopSpan is the same as noop.Span, except with a "valid" span context
// (has a non-zero trace and span ID).
//
// Adding this into a context as follows:
//
//	ctx = oteltrace.ContextWithSpan(ctx, trace.ValidNoopSpan{})
//
// will prevent some usages of the global tracer provider by libraries such
// as otelhttp, which only uses the global provider if the context's span
// is "invalid".
type ValidNoopSpan struct {
	noop.Span
}

var noopTraceID = oteltrace.TraceID{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

var noopSpanID = oteltrace.SpanID{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

// SpanContext implements trace.Span.
func (n ValidNoopSpan) SpanContext() oteltrace.SpanContext {
	return n.Span.SpanContext().WithTraceID(noopTraceID).WithSpanID(noopSpanID)
}

var _ oteltrace.Span = ValidNoopSpan{}

func IsOtelSDKDisabled() bool {
	return os.Getenv("OTEL_SDK_DISABLED") == "true"
}
