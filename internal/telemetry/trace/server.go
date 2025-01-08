package trace

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/pomerium/pomerium/internal/log"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
)

const localExporterMetadataKey = "x-local-exporter"

// Export implements ptraceotlp.GRPCServer.
func (srv *ExporterServer) Export(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	if srv.observer != nil {
		isLocal := len(metadata.ValueFromIncomingContext(ctx, localExporterMetadataKey)) != 0
		if !isLocal {
			for _, res := range req.ResourceSpans {
				for _, scope := range res.ScopeSpans {
					for _, span := range scope.Spans {
						if id, ok := ToSpanID(span.SpanId); ok {
							srv.observer.Observe(id)
						}
					}
				}
			}
		}
	}
	if err := srv.remoteClient.UploadTraces(ctx, req.GetResourceSpans()); err != nil {
		log.Ctx(ctx).Err(err).Msg("error uploading traces")
		return nil, err
	}
	return &coltracepb.ExportTraceServiceResponse{}, nil
}

type ExporterServer struct {
	coltracepb.UnimplementedTraceServiceServer
	server       *grpc.Server
	observer     *spanObserver
	remoteClient otlptrace.Client
	cc           *grpc.ClientConn
}

func NewServer(ctx context.Context) *ExporterServer {
	sys := systemContextFromContext(ctx)
	ex := &ExporterServer{
		remoteClient: sys.options.RemoteClient,
		observer:     sys.observer,
		server:       grpc.NewServer(grpc.Creds(insecure.NewCredentials())),
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
		otlptracegrpc.WithHeaders(map[string]string{
			localExporterMetadataKey: "1",
		}),
	)
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
	if err := WaitForSpans(ctx, 30*time.Second); err != nil {
		errs = append(errs, err)
	}
	if err := srv.remoteClient.Stop(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
