package scenarios

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/internal/testutil/tracetest"
)

type RecordedExportRequest struct {
	Request  *coltracepb.ExportTraceServiceRequest
	Metadata map[string][]string
}
type RecordedExportRequests []RecordedExportRequest

func (s RecordedExportRequests) AsExportTraceServiceRequests() []*coltracepb.ExportTraceServiceRequest {
	out := make([]*coltracepb.ExportTraceServiceRequest, len(s))
	for i, v := range s {
		out[i] = v.Request
	}
	return out
}

type OTLPTraceReceiver struct {
	coltracepb.UnimplementedTraceServiceServer

	mu               sync.Mutex
	receivedRequests RecordedExportRequests
	grpcUpstream     values.MutableValue[upstreams.GRPCUpstream]
	httpUpstream     values.MutableValue[upstreams.HTTPUpstream]
}

func NewOTLPTraceReceiver() *OTLPTraceReceiver {
	return &OTLPTraceReceiver{
		grpcUpstream: values.Deferred[upstreams.GRPCUpstream](),
		httpUpstream: values.Deferred[upstreams.HTTPUpstream](),
	}
}

// Export implements v1.TraceServiceServer.
func (rec *OTLPTraceReceiver) Export(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	md, _ := metadata.FromIncomingContext(ctx)
	rec.receivedRequests = append(rec.receivedRequests, RecordedExportRequest{
		Request:  req,
		Metadata: md,
	})
	return &coltracepb.ExportTraceServiceResponse{}, nil
}

// Attach implements testenv.Modifier.
func (rec *OTLPTraceReceiver) Attach(ctx context.Context) {
	env := testenv.EnvFromContext(ctx)

	// NB: we cannot install tracing middleware into the receiver server, since
	// it will cause a feedback loop of spans created when exporting other spans

	grpcUpstream := upstreams.GRPC(nil,
		upstreams.WithDisplayName("OTLP GRPC Receiver"),
		upstreams.WithDelayedShutdown(),
		upstreams.WithNoClientTracing(),
		upstreams.WithNoServerTracing(),
	)
	httpUpstream := upstreams.HTTP(nil,
		upstreams.WithDisplayName("OTLP HTTP Receiver"),
		upstreams.WithDelayedShutdown(),
		upstreams.WithNoClientTracing(),
		upstreams.WithNoServerTracing(),
	)

	coltracepb.RegisterTraceServiceServer(grpcUpstream, rec)
	httpUpstream.Handle("/v1/traces", rec.handleV1Traces)
	env.AddUpstream(grpcUpstream)
	env.AddUpstream(httpUpstream)
	rec.grpcUpstream.Resolve(grpcUpstream)
	rec.httpUpstream.Resolve(httpUpstream)
}

// Modify implements testenv.Modifier.
func (rec *OTLPTraceReceiver) Modify(cfg *config.Config) {
	cfg.Options.Tracing.OtelTracesExporter = proto.String("otlp")
	cfg.Options.Tracing.OtelExporterOtlpTracesEndpoint = proto.String(rec.GRPCEndpointURL().Value())
	cfg.Options.Tracing.OtelExporterOtlpTracesProtocol = proto.String("grpc")
}

func (rec *OTLPTraceReceiver) handleV1Traces(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/x-protobuf" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid content type"))
		return
	}
	reader := r.Body
	if r.Header.Get("Content-Encoding") == "gzip" {
		var err error
		reader, err = gzip.NewReader(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(err.Error()))
			return
		}
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(err.Error()))
		return
	}
	var req coltracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(data, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(err.Error()))
		return
	}

	resp, err := rec.Export(metadata.NewIncomingContext(r.Context(), metadata.MD(r.Header)), &req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}
	respData, err := proto.Marshal(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respData)
}

func (rec *OTLPTraceReceiver) ReceivedRequests() []RecordedExportRequest {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return rec.receivedRequests
}

func (rec *OTLPTraceReceiver) PeekResourceSpans() []*tracev1.ResourceSpans {
	rec.mu.Lock()
	defer rec.mu.Unlock()

	return rec.peekResourceSpansLocked()
}

func (rec *OTLPTraceReceiver) peekResourceSpansLocked() []*tracev1.ResourceSpans {
	return tracetest.FlattenExportRequests(rec.receivedRequests.AsExportTraceServiceRequests())
}

func (rec *OTLPTraceReceiver) FlushResourceSpans() []*tracev1.ResourceSpans {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	spans := rec.peekResourceSpansLocked()
	rec.receivedRequests = nil
	return spans
}

// GRPCEndpointURL returns a url suitable for use with the environment variable
// $OTEL_EXPORTER_OTLP_TRACES_ENDPOINT or with [otlptracegrpc.WithEndpointURL].
func (rec *OTLPTraceReceiver) GRPCEndpointURL() values.Value[string] {
	return values.Chain(rec.grpcUpstream, upstreams.GRPCUpstream.Addr, func(addr string) string {
		return fmt.Sprintf("http://%s", addr)
	})
}

// GRPCEndpointURL returns a url suitable for use with the environment variable
// $OTEL_EXPORTER_OTLP_TRACES_ENDPOINT or with [otlptracehttp.WithEndpointURL].
func (rec *OTLPTraceReceiver) HTTPEndpointURL() values.Value[string] {
	return values.Chain(rec.httpUpstream, upstreams.HTTPUpstream.Addr, func(addr string) string {
		return fmt.Sprintf("http://%s/v1/traces", addr)
	})
}

func (rec *OTLPTraceReceiver) NewGRPCClient(opts ...otlptracegrpc.Option) otlptrace.Client {
	return &deferredClient{
		client: values.Bind(rec.grpcUpstream, func(up upstreams.GRPCUpstream) otlptrace.Client {
			return otlptracegrpc.NewClient(append(opts,
				otlptracegrpc.WithGRPCConn(up.DirectConnect()),
				otlptracegrpc.WithTimeout(1*time.Minute),
			)...)
		}),
	}
}

func (rec *OTLPTraceReceiver) NewHTTPClient(opts ...otlptracehttp.Option) otlptrace.Client {
	return &deferredClient{
		client: values.Chain(rec.httpUpstream, upstreams.HTTPUpstream.Addr, func(addr string) otlptrace.Client {
			return otlptracehttp.NewClient(append(opts,
				otlptracehttp.WithEndpointURL(fmt.Sprintf("http://%s/v1/traces", addr)),
				otlptracehttp.WithTimeout(1*time.Minute),
			)...)
		}),
	}
}

type deferredClient struct {
	client values.Value[otlptrace.Client]
}

// Start implements otlptrace.Client.
func (o *deferredClient) Start(ctx context.Context) error {
	return o.client.Value().Start(ctx)
}

// Stop implements otlptrace.Client.
func (o *deferredClient) Stop(ctx context.Context) error {
	return o.client.Value().Stop(ctx)
}

// UploadTraces implements otlptrace.Client.
func (o *deferredClient) UploadTraces(ctx context.Context, protoSpans []*tracev1.ResourceSpans) error {
	return o.client.Value().UploadTraces(ctx, protoSpans)
}

var _ otlptrace.Client = (*deferredClient)(nil)
