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
	url string

	mgr *ClientConnectionManager
}

// NewForwardingServer creates a new server that forwards all requests to another server.
func NewForwardingServer(cfg *config.Config, rawURL string) Server {
	srv := &forwardingServer{url: rawURL, mgr: NewClientConnectionManager()}
	if cfg != nil {
		srv.mgr.Update(context.Background(), cfg, []string{rawURL})
	}
	return srv
}

func (srv *forwardingServer) AcquireLease(ctx context.Context, req *databrokerpb.AcquireLeaseRequest) (*databrokerpb.AcquireLeaseResponse, error) {
	cc, err := srv.mgr.GetClient(srv.url)
	if err != nil {
		return nil, err
	}
	return forwardUnary(ctx, func(ctx context.Context) (*databrokerpb.AcquireLeaseResponse, error) {
		return databrokerpb.NewDataBrokerServiceClient(cc).AcquireLease(ctx, req)
	})
}

func (srv *forwardingServer) Get(ctx context.Context, req *databrokerpb.GetRequest) (*databrokerpb.GetResponse, error) {
	cc, err := srv.mgr.GetClient(srv.url)
	if err != nil {
		return nil, err
	}
	return forwardUnary(ctx, func(ctx context.Context) (*databrokerpb.GetResponse, error) {
		return databrokerpb.NewDataBrokerServiceClient(cc).Get(ctx, req)
	})
}

func (srv *forwardingServer) List(ctx context.Context, req *registrypb.ListRequest) (*registrypb.ServiceList, error) {
	cc, err := srv.mgr.GetClient(srv.url)
	if err != nil {
		return nil, err
	}
	return forwardUnary(ctx, func(ctx context.Context) (*registrypb.ServiceList, error) {
		return registrypb.NewRegistryClient(cc).List(ctx, req)
	})
}

func (srv *forwardingServer) ListTypes(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ListTypesResponse, error) {
	cc, err := srv.mgr.GetClient(srv.url)
	if err != nil {
		return nil, err
	}
	return forwardUnary(ctx, func(ctx context.Context) (*databrokerpb.ListTypesResponse, error) {
		return databrokerpb.NewDataBrokerServiceClient(cc).ListTypes(ctx, req)
	})
}

func (srv *forwardingServer) Patch(ctx context.Context, req *databrokerpb.PatchRequest) (*databrokerpb.PatchResponse, error) {
	cc, err := srv.mgr.GetClient(srv.url)
	if err != nil {
		return nil, err
	}
	return forwardUnary(ctx, func(ctx context.Context) (*databrokerpb.PatchResponse, error) {
		return databrokerpb.NewDataBrokerServiceClient(cc).Patch(ctx, req)
	})
}

func (srv *forwardingServer) Put(ctx context.Context, req *databrokerpb.PutRequest) (*databrokerpb.PutResponse, error) {
	cc, err := srv.mgr.GetClient(srv.url)
	if err != nil {
		return nil, err
	}
	return forwardUnary(ctx, func(ctx context.Context) (*databrokerpb.PutResponse, error) {
		return databrokerpb.NewDataBrokerServiceClient(cc).Put(ctx, req)
	})
}

func (srv *forwardingServer) Query(ctx context.Context, req *databrokerpb.QueryRequest) (*databrokerpb.QueryResponse, error) {
	cc, err := srv.mgr.GetClient(srv.url)
	if err != nil {
		return nil, err
	}
	return forwardUnary(ctx, func(ctx context.Context) (*databrokerpb.QueryResponse, error) {
		return databrokerpb.NewDataBrokerServiceClient(cc).Query(ctx, req)
	})
}

func (srv *forwardingServer) ReleaseLease(ctx context.Context, req *databrokerpb.ReleaseLeaseRequest) (*emptypb.Empty, error) {
	cc, err := srv.mgr.GetClient(srv.url)
	if err != nil {
		return nil, err
	}
	return forwardUnary(ctx, func(ctx context.Context) (*emptypb.Empty, error) {
		return databrokerpb.NewDataBrokerServiceClient(cc).ReleaseLease(ctx, req)
	})
}

func (srv *forwardingServer) RenewLease(ctx context.Context, req *databrokerpb.RenewLeaseRequest) (*emptypb.Empty, error) {
	cc, err := srv.mgr.GetClient(srv.url)
	if err != nil {
		return nil, err
	}
	return forwardUnary(ctx, func(ctx context.Context) (*emptypb.Empty, error) {
		return databrokerpb.NewDataBrokerServiceClient(cc).RenewLease(ctx, req)
	})
}

func (srv *forwardingServer) Report(ctx context.Context, req *registrypb.RegisterRequest) (*registrypb.RegisterResponse, error) {
	cc, err := srv.mgr.GetClient(srv.url)
	if err != nil {
		return nil, err
	}
	return forwardUnary(ctx, func(ctx context.Context) (*registrypb.RegisterResponse, error) {
		return registrypb.NewRegistryClient(cc).Report(ctx, req)
	})
}

func (srv *forwardingServer) ServerInfo(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ServerInfoResponse, error) {
	cc, err := srv.mgr.GetClient(srv.url)
	if err != nil {
		return nil, err
	}
	return forwardUnary(ctx, func(ctx context.Context) (*databrokerpb.ServerInfoResponse, error) {
		return databrokerpb.NewDataBrokerServiceClient(cc).ServerInfo(ctx, req)
	})
}

func (srv *forwardingServer) SetOptions(ctx context.Context, req *databrokerpb.SetOptionsRequest) (*databrokerpb.SetOptionsResponse, error) {
	cc, err := srv.mgr.GetClient(srv.url)
	if err != nil {
		return nil, err
	}
	return forwardUnary(ctx, func(ctx context.Context) (*databrokerpb.SetOptionsResponse, error) {
		return databrokerpb.NewDataBrokerServiceClient(cc).SetOptions(ctx, req)
	})
}

func (srv *forwardingServer) Sync(req *databrokerpb.SyncRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncResponse]) error {
	cc, err := srv.mgr.GetClient(srv.url)
	if err != nil {
		return err
	}
	return forwardStream(stream, func(ctx context.Context) (grpc.ServerStreamingClient[databrokerpb.SyncResponse], error) {
		return databrokerpb.NewDataBrokerServiceClient(cc).Sync(ctx, req)
	})
}

func (srv *forwardingServer) SyncLatest(req *databrokerpb.SyncLatestRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncLatestResponse]) error {
	cc, err := srv.mgr.GetClient(srv.url)
	if err != nil {
		return err
	}
	return forwardStream(stream, func(ctx context.Context) (grpc.ServerStreamingClient[databrokerpb.SyncLatestResponse], error) {
		return databrokerpb.NewDataBrokerServiceClient(cc).SyncLatest(ctx, req)
	})
}

func (srv *forwardingServer) Watch(req *registrypb.ListRequest, stream grpc.ServerStreamingServer[registrypb.ServiceList]) error {
	cc, err := srv.mgr.GetClient(srv.url)
	if err != nil {
		return err
	}
	return forwardStream(stream, func(ctx context.Context) (grpc.ServerStreamingClient[registrypb.ServiceList], error) {
		return registrypb.NewRegistryClient(cc).Watch(ctx, req)
	})
}

func (srv *forwardingServer) Stop() {
	srv.mgr.Stop()
}

func (srv *forwardingServer) OnConfigChange(ctx context.Context, cfg *config.Config) {
	srv.mgr.Update(ctx, cfg, []string{srv.url})
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
