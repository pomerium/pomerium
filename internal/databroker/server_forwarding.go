package databroker

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

const maxForwards = 1

type forwardingServer struct {
	cc grpc.ClientConnInterface
}

// NewForwardingServer creates a new server that forwards all requests to another server.
func NewForwardingServer(cc grpc.ClientConnInterface) Server {
	return &forwardingServer{cc}
}

func (srv *forwardingServer) AcquireLease(ctx context.Context, req *databrokerpb.AcquireLeaseRequest) (*databrokerpb.AcquireLeaseResponse, error) {
	return forwardUnary(ctx, func(ctx context.Context) (*databrokerpb.AcquireLeaseResponse, error) {
		return databrokerpb.NewDataBrokerServiceClient(srv.cc).AcquireLease(ctx, req)
	})
}

func (srv *forwardingServer) Get(ctx context.Context, req *databrokerpb.GetRequest) (*databrokerpb.GetResponse, error) {
	return forwardUnary(ctx, func(ctx context.Context) (*databrokerpb.GetResponse, error) {
		return databrokerpb.NewDataBrokerServiceClient(srv.cc).Get(ctx, req)
	})
}

func (srv *forwardingServer) List(ctx context.Context, req *registrypb.ListRequest) (*registrypb.ServiceList, error) {
	return forwardUnary(ctx, func(ctx context.Context) (*registrypb.ServiceList, error) {
		return registrypb.NewRegistryClient(srv.cc).List(ctx, req)
	})
}

func (srv *forwardingServer) ListTypes(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ListTypesResponse, error) {
	return forwardUnary(ctx, func(ctx context.Context) (*databrokerpb.ListTypesResponse, error) {
		return databrokerpb.NewDataBrokerServiceClient(srv.cc).ListTypes(ctx, req)
	})
}

func (srv *forwardingServer) Patch(ctx context.Context, req *databrokerpb.PatchRequest) (*databrokerpb.PatchResponse, error) {
	return forwardUnary(ctx, func(ctx context.Context) (*databrokerpb.PatchResponse, error) {
		return databrokerpb.NewDataBrokerServiceClient(srv.cc).Patch(ctx, req)
	})
}

func (srv *forwardingServer) Put(ctx context.Context, req *databrokerpb.PutRequest) (*databrokerpb.PutResponse, error) {
	return forwardUnary(ctx, func(ctx context.Context) (*databrokerpb.PutResponse, error) {
		return databrokerpb.NewDataBrokerServiceClient(srv.cc).Put(ctx, req)
	})
}

func (srv *forwardingServer) Query(ctx context.Context, req *databrokerpb.QueryRequest) (*databrokerpb.QueryResponse, error) {
	return forwardUnary(ctx, func(ctx context.Context) (*databrokerpb.QueryResponse, error) {
		return databrokerpb.NewDataBrokerServiceClient(srv.cc).Query(ctx, req)
	})
}

func (srv *forwardingServer) ReleaseLease(ctx context.Context, req *databrokerpb.ReleaseLeaseRequest) (*emptypb.Empty, error) {
	return forwardUnary(ctx, func(ctx context.Context) (*emptypb.Empty, error) {
		return databrokerpb.NewDataBrokerServiceClient(srv.cc).ReleaseLease(ctx, req)
	})
}

func (srv *forwardingServer) RenewLease(ctx context.Context, req *databrokerpb.RenewLeaseRequest) (*emptypb.Empty, error) {
	return forwardUnary(ctx, func(ctx context.Context) (*emptypb.Empty, error) {
		return databrokerpb.NewDataBrokerServiceClient(srv.cc).RenewLease(ctx, req)
	})
}

func (srv *forwardingServer) Report(ctx context.Context, req *registrypb.RegisterRequest) (*registrypb.RegisterResponse, error) {
	return forwardUnary(ctx, func(ctx context.Context) (*registrypb.RegisterResponse, error) {
		return registrypb.NewRegistryClient(srv.cc).Report(ctx, req)
	})
}

func (srv *forwardingServer) ServerInfo(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ServerInfoResponse, error) {
	return forwardUnary(ctx, func(ctx context.Context) (*databrokerpb.ServerInfoResponse, error) {
		return databrokerpb.NewDataBrokerServiceClient(srv.cc).ServerInfo(ctx, req)
	})
}

func (srv *forwardingServer) SetOptions(ctx context.Context, req *databrokerpb.SetOptionsRequest) (*databrokerpb.SetOptionsResponse, error) {
	return forwardUnary(ctx, func(ctx context.Context) (*databrokerpb.SetOptionsResponse, error) {
		return databrokerpb.NewDataBrokerServiceClient(srv.cc).SetOptions(ctx, req)
	})
}

func (srv *forwardingServer) Sync(req *databrokerpb.SyncRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncResponse]) error {
	return forwardStream(stream, func(ctx context.Context) (grpc.ServerStreamingClient[databrokerpb.SyncResponse], error) {
		return databrokerpb.NewDataBrokerServiceClient(srv.cc).Sync(ctx, req)
	})
}

func (srv *forwardingServer) SyncLatest(req *databrokerpb.SyncLatestRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncLatestResponse]) error {
	return forwardStream(stream, func(ctx context.Context) (grpc.ServerStreamingClient[databrokerpb.SyncLatestResponse], error) {
		return databrokerpb.NewDataBrokerServiceClient(srv.cc).SyncLatest(ctx, req)
	})
}

func (srv *forwardingServer) Watch(req *registrypb.ListRequest, stream grpc.ServerStreamingServer[registrypb.ServiceList]) error {
	return forwardStream(stream, func(ctx context.Context) (grpc.ServerStreamingClient[registrypb.ServiceList], error) {
		return registrypb.NewRegistryClient(srv.cc).Watch(ctx, req)
	})
}

func (srv *forwardingServer) Stop() {
}

func (srv *forwardingServer) OnConfigChange(_ context.Context, _ *config.Config) {
}

func checkMaxForwards(ctx context.Context) error {
	forwardedFor := grpcutil.ForwardedForFromIncoming(ctx)
	if len(forwardedFor) >= maxForwards {
		return databrokerpb.ErrForwardLimitExceeded
	}
	return nil
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

	forwardedFor := grpcutil.ForwardedForFromIncoming(ctx)
	if p, ok := peer.FromContext(ctx); ok {
		forwardedFor = append(forwardedFor, p.Addr.String())
	} else {
		forwardedFor = append(forwardedFor, "127.0.0.1")
	}
	ctx = grpcutil.WithOutgoingForwardedFor(ctx, forwardedFor)

	return ctx
}

func forwardUnary[T any](ctx context.Context, fn func(ctx context.Context) (T, error)) (T, error) {
	if err := checkMaxForwards(ctx); err != nil {
		var zero T
		return zero, err
	}
	ctx = forwardMetadata(ctx)
	return fn(ctx)
}

func forwardStream[T any](
	serverStream grpc.ServerStreamingServer[T],
	getClientStream func(context.Context) (grpc.ServerStreamingClient[T], error),
) error {
	ctx, cancel := context.WithCancel(serverStream.Context())
	defer cancel()

	if err := checkMaxForwards(ctx); err != nil {
		return err
	}

	clientStream, err := getClientStream(forwardMetadata(ctx))
	if err != nil {
		return err
	}

	for {
		msg, err := clientStream.Recv()
		if err != nil {
			return err
		}

		err = serverStream.Send(msg)
		if err != nil {
			return err
		}
	}
}
