package scenarios

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type OTLPTraceReceiver struct {
	coltracepb.UnimplementedTraceServiceServer
	listener values.MutableValue[*bufconn.Listener]

	mu               sync.Mutex
	receivedRequests []*coltracepb.ExportTraceServiceRequest
}

// Export implements v1.TraceServiceServer.
func (rec *OTLPTraceReceiver) Export(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.receivedRequests = append(rec.receivedRequests, req)
	return &coltracepb.ExportTraceServiceResponse{}, nil
}

// Attach implements testenv.Modifier.
func (rec *OTLPTraceReceiver) Attach(ctx context.Context) {
	env := testenv.EnvFromContext(ctx)
	listener := bufconn.Listen(4096)
	rec.listener.Resolve(listener)
	grpcServer := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
	coltracepb.RegisterTraceServiceServer(grpcServer, rec)

	env.AddTask(testenv.TaskFunc(func(ctx context.Context) error {
		exitTask := make(chan struct{})
		done := make(chan error, 1)
		env.OnStateChanged(testenv.Stopping, func() {
			close(exitTask)
		})
		env.OnStateChanged(testenv.Stopped, func() {
			grpcServer.GracefulStop()
			if err := <-done; err != nil {
				log.Ctx(ctx).Err(err).Msg("error stopping trace receiver")
			}
		})
		go func() {
			done <- grpcServer.Serve(listener)
		}()
		select {
		case <-exitTask:
			return nil
		case err := <-done:
			return err
		}
	}))
}

// Modify implements testenv.Modifier.
func (rec *OTLPTraceReceiver) Modify(cfg *config.Config) {}

func (rec *OTLPTraceReceiver) ReceivedRequests() []*coltracepb.ExportTraceServiceRequest {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return rec.receivedRequests
}

func (rec *OTLPTraceReceiver) ResourceSpans() []*tracev1.ResourceSpans {
	rec.mu.Lock()
	defer rec.mu.Unlock()

	res := trace.NewTraceBuffer()
	for _, req := range rec.receivedRequests {
		for _, resource := range req.ResourceSpans {
			resInfo := trace.NewResourceInfo(resource.Resource, resource.SchemaUrl)
			for _, scope := range resource.ScopeSpans {
				scopeInfo := trace.NewScopeInfo(scope.Scope, scope.SchemaUrl)
				for _, span := range scope.Spans {
					res.Insert(resInfo, scopeInfo, span)
				}
			}
		}
	}
	return res.Flush()
}

func (rec *OTLPTraceReceiver) NewClient() otlptrace.Client {
	return &otlpTraceClient{
		client: values.Bind(rec.listener, func(listener *bufconn.Listener) otlptrace.Client {
			cc, err := grpc.NewClient("passthrough://ignore",
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
					return listener.Dial()
				}), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				panic(err)
			}
			return otlptracegrpc.NewClient(
				otlptracegrpc.WithGRPCConn(cc),
				otlptracegrpc.WithTimeout(1*time.Minute),
			)
		}),
	}
}

func NewOTLPTraceReceiver() *OTLPTraceReceiver {
	return &OTLPTraceReceiver{
		listener: values.Deferred[*bufconn.Listener](),
	}
}

type otlpTraceClient struct {
	client values.Value[otlptrace.Client]
}

// Start implements otlptrace.Client.
func (o *otlpTraceClient) Start(ctx context.Context) error {
	return o.client.Value().Start(ctx)
}

// Stop implements otlptrace.Client.
func (o *otlpTraceClient) Stop(ctx context.Context) error {
	return o.client.Value().Stop(ctx)
}

// UploadTraces implements otlptrace.Client.
func (o *otlpTraceClient) UploadTraces(ctx context.Context, protoSpans []*tracev1.ResourceSpans) error {
	return o.client.Value().UploadTraces(ctx, protoSpans)
}

var _ otlptrace.Client = (*otlpTraceClient)(nil)
