package databroker

import (
	"context"
	"errors"
	"io"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/telemetry"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

type clusteredFollowerServer struct {
	telemetry telemetry.Component
	local     Server
	cc        grpc.ClientConnInterface
}

func newClusteredFollowerServer(tracerProvider oteltrace.TracerProvider, local Server, cc grpc.ClientConnInterface) Server {
	return &clusteredFollowerServer{
		telemetry: *telemetry.NewComponent(tracerProvider, zerolog.TraceLevel, "databroker-clustered-follower-server"),
		local:     local, cc: cc,
	}
}

func (srv *clusteredFollowerServer) AcquireLease(ctx context.Context, req *databrokerpb.AcquireLeaseRequest) (res *databrokerpb.AcquireLeaseResponse, err error) {
	return res, srv.invoke(ctx, "AcquireLease", func(ctx context.Context) error {
		var err error
		res, err = databrokerpb.NewDataBrokerServiceClient(srv.cc).AcquireLease(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Get(ctx context.Context, req *databrokerpb.GetRequest) (res *databrokerpb.GetResponse, err error) {
	return res, srv.invoke(ctx, "Get", func(ctx context.Context) error {
		var err error
		res, err = databrokerpb.NewDataBrokerServiceClient(srv.cc).Get(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) List(ctx context.Context, req *registrypb.ListRequest) (res *registrypb.ServiceList, err error) {
	return res, srv.invoke(ctx, "List", func(ctx context.Context) error {
		var err error
		res, err = registrypb.NewRegistryClient(srv.cc).List(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) ListTypes(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ListTypesResponse, err error) {
	return res, srv.invoke(ctx, "ListTypes", func(ctx context.Context) error {
		var err error
		res, err = databrokerpb.NewDataBrokerServiceClient(srv.cc).ListTypes(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Patch(ctx context.Context, req *databrokerpb.PatchRequest) (res *databrokerpb.PatchResponse, err error) {
	return res, srv.invoke(ctx, "Patch", func(ctx context.Context) error {
		var err error
		res, err = databrokerpb.NewDataBrokerServiceClient(srv.cc).Patch(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Put(ctx context.Context, req *databrokerpb.PutRequest) (res *databrokerpb.PutResponse, err error) {
	return res, srv.invoke(ctx, "Put", func(ctx context.Context) error {
		var err error
		res, err = databrokerpb.NewDataBrokerServiceClient(srv.cc).Put(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Query(ctx context.Context, req *databrokerpb.QueryRequest) (res *databrokerpb.QueryResponse, err error) {
	return res, srv.invoke(ctx, "Query", func(ctx context.Context) error {
		var err error
		res, err = databrokerpb.NewDataBrokerServiceClient(srv.cc).Query(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) ReleaseLease(ctx context.Context, req *databrokerpb.ReleaseLeaseRequest) (res *emptypb.Empty, err error) {
	return res, srv.invoke(ctx, "ReleaseLease", func(ctx context.Context) error {
		var err error
		res, err = databrokerpb.NewDataBrokerServiceClient(srv.cc).ReleaseLease(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) RenewLease(ctx context.Context, req *databrokerpb.RenewLeaseRequest) (res *emptypb.Empty, err error) {
	return res, srv.invoke(ctx, "RenewLease", func(ctx context.Context) error {
		var err error
		res, err = databrokerpb.NewDataBrokerServiceClient(srv.cc).RenewLease(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Report(ctx context.Context, req *registrypb.RegisterRequest) (res *registrypb.RegisterResponse, err error) {
	return res, srv.invoke(ctx, "Report", func(ctx context.Context) error {
		var err error
		res, err = registrypb.NewRegistryClient(srv.cc).Report(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) ServerInfo(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ServerInfoResponse, err error) {
	return res, srv.invoke(ctx, "ServerInfo", func(ctx context.Context) error {
		var err error
		res, err = databrokerpb.NewDataBrokerServiceClient(srv.cc).ServerInfo(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) SetOptions(ctx context.Context, req *databrokerpb.SetOptionsRequest) (res *databrokerpb.SetOptionsResponse, err error) {
	return res, srv.invoke(ctx, "SetOptions", func(ctx context.Context) error {
		var err error
		res, err = databrokerpb.NewDataBrokerServiceClient(srv.cc).SetOptions(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Sync(req *databrokerpb.SyncRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncResponse]) error {
	return srv.invoke(stream.Context(), "Sync", func(ctx context.Context) error {
		return forwardStream(ctx, stream, databrokerpb.NewDataBrokerServiceClient(srv.cc).Sync, req)
	})
}

func (srv *clusteredFollowerServer) SyncLatest(req *databrokerpb.SyncLatestRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncLatestResponse]) error {
	return srv.invoke(stream.Context(), "SyncLatest", func(ctx context.Context) error {
		return forwardStream(ctx, stream, databrokerpb.NewDataBrokerServiceClient(srv.cc).SyncLatest, req)
	})
}

func (srv *clusteredFollowerServer) Watch(req *registrypb.ListRequest, stream grpc.ServerStreamingServer[registrypb.ServiceList]) error {
	return srv.invoke(stream.Context(), "Watch", func(ctx context.Context) error {
		return forwardStream(ctx, stream, registrypb.NewRegistryClient(srv.cc).Watch, req)
	})
}

func (srv *clusteredFollowerServer) Stop()                                              {}
func (srv *clusteredFollowerServer) OnConfigChange(_ context.Context, _ *config.Config) {}

func (srv *clusteredFollowerServer) invoke(ctx context.Context, methodName string, fn func(context.Context) error) error {
	ctx, op := srv.telemetry.Start(ctx, "Forward",
		attribute.String("method", methodName))
	defer op.Complete()

	err := fn(forwardMetadata(ctx))

	// only treat internal errors as errors for the sake of the operation
	if status.Code(err) == codes.Internal {
		return op.Failure(err)
	}

	return err
}

func forwardMetadata(ctx context.Context) context.Context {
	if inMD, ok := metadata.FromIncomingContext(ctx); ok {
		outMD, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			outMD = make(metadata.MD)
		}
		for k, vs := range inMD {
			outMD.Append(k, vs...)
		}
		ctx = metadata.NewOutgoingContext(ctx, outMD)
	}

	return ctx
}

func forwardStream[Res any, Req any](
	ctx context.Context,
	serverStream grpc.ServerStreamingServer[Res],
	getClientStream func(ctx context.Context, req Req, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Res], error),
	req Req,
	opts ...grpc.CallOption,
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	clientStream, err := getClientStream(forwardMetadata(ctx), req, opts...)
	if err != nil {
		return err
	}

	for {
		msg, err := clientStream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}

		err = serverStream.Send(msg)
		if err != nil {
			return err
		}
	}
}
