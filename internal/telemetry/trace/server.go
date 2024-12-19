package trace

import (
	"context"
	"errors"
	"net"
	"time"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Export implements ptraceotlp.GRPCServer.
func (srv *ExporterServer) Export(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	if err := srv.spanExportQueue.Enqueue(ctx, req); err != nil {
		return nil, err
	}
	return &coltracepb.ExportTraceServiceResponse{}, nil
}

type ExporterServer struct {
	coltracepb.UnimplementedTraceServiceServer
	spanExportQueue *SpanExportQueue
	server          *grpc.Server
	remoteClient    otlptrace.Client
	cc              *grpc.ClientConn
}

func NewServer(ctx context.Context, remoteClient otlptrace.Client) *ExporterServer {
	ex := &ExporterServer{
		spanExportQueue: NewSpanExportQueue(ctx, remoteClient),
		remoteClient:    remoteClient,
		server:          grpc.NewServer(grpc.Creds(insecure.NewCredentials())),
	}
	coltracepb.RegisterTraceServiceServer(ex.server, ex)
	return ex
}

func (srv *ExporterServer) Start(ctx context.Context) {
	lis := bufconn.Listen(4096)
	go func() {
		if err := srv.remoteClient.Start(ctx); err != nil {
			panic(err)
		}
		_ = srv.server.Serve(lis)
	}()
	cc, err := grpc.NewClient("passthrough://ignore",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		panic(err)
	}
	srv.cc = cc
}

func (srv *ExporterServer) NewClient() otlptrace.Client {
	return otlptracegrpc.NewClient(
		otlptracegrpc.WithGRPCConn(srv.cc),
		otlptracegrpc.WithTimeout(1*time.Minute),
	)
}

func (srv *ExporterServer) SpanProcessors() []sdktrace.SpanProcessor {
	return []sdktrace.SpanProcessor{srv.spanExportQueue.tracker}
}

func (srv *ExporterServer) Shutdown(ctx context.Context) error {
	stopped := make(chan struct{})
	go func() {
		srv.server.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	var errs []error
	if err := srv.spanExportQueue.WaitForSpans(30 * time.Second); err != nil {
		errs = append(errs, err)
	}
	if err := srv.spanExportQueue.Close(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := srv.remoteClient.Stop(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
