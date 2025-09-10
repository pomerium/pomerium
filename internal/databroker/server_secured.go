package databroker

import (
	"context"
	"slices"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

type securedServer struct {
	underlying Server
	sharedKey  atomic.Pointer[[]byte]
}

// NewSecuredServer creates a server that requires a signed JWT for every method.
func NewSecuredServer(underlying Server) Server {
	srv := &securedServer{
		underlying: underlying,
	}
	return srv
}

func (srv *securedServer) AcquireLease(ctx context.Context, req *databrokerpb.AcquireLeaseRequest) (*databrokerpb.AcquireLeaseResponse, error) {
	if err := srv.authorize(ctx); err != nil {
		return nil, err
	}
	return srv.underlying.AcquireLease(ctx, req)
}

func (srv *securedServer) Clear(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ClearResponse, error) {
	if err := srv.authorize(ctx); err != nil {
		return nil, err
	}
	return srv.underlying.Clear(ctx, req)
}

func (srv *securedServer) Get(ctx context.Context, req *databrokerpb.GetRequest) (*databrokerpb.GetResponse, error) {
	if err := srv.authorize(ctx); err != nil {
		return nil, err
	}
	return srv.underlying.Get(ctx, req)
}

func (srv *securedServer) GetCheckpoint(ctx context.Context, req *emptypb.Empty) (*databrokerpb.Checkpoint, error) {
	if err := srv.authorize(ctx); err != nil {
		return nil, err
	}
	return srv.underlying.GetCheckpoint(ctx, req)
}

func (srv *securedServer) List(ctx context.Context, req *registrypb.ListRequest) (*registrypb.ServiceList, error) {
	if err := srv.authorize(ctx); err != nil {
		return nil, err
	}
	return srv.underlying.List(ctx, req)
}

func (srv *securedServer) ListTypes(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ListTypesResponse, error) {
	if err := srv.authorize(ctx); err != nil {
		return nil, err
	}
	return srv.underlying.ListTypes(ctx, req)
}

func (srv *securedServer) Patch(ctx context.Context, req *databrokerpb.PatchRequest) (*databrokerpb.PatchResponse, error) {
	if err := srv.authorize(ctx); err != nil {
		return nil, err
	}
	return srv.underlying.Patch(ctx, req)
}

func (srv *securedServer) Put(ctx context.Context, req *databrokerpb.PutRequest) (*databrokerpb.PutResponse, error) {
	if err := srv.authorize(ctx); err != nil {
		return nil, err
	}
	return srv.underlying.Put(ctx, req)
}

func (srv *securedServer) Query(ctx context.Context, req *databrokerpb.QueryRequest) (*databrokerpb.QueryResponse, error) {
	if err := srv.authorize(ctx); err != nil {
		return nil, err
	}
	return srv.underlying.Query(ctx, req)
}

func (srv *securedServer) ReleaseLease(ctx context.Context, req *databrokerpb.ReleaseLeaseRequest) (*emptypb.Empty, error) {
	if err := srv.authorize(ctx); err != nil {
		return nil, err
	}
	return srv.underlying.ReleaseLease(ctx, req)
}

func (srv *securedServer) RenewLease(ctx context.Context, req *databrokerpb.RenewLeaseRequest) (*emptypb.Empty, error) {
	if err := srv.authorize(ctx); err != nil {
		return nil, err
	}
	return srv.underlying.RenewLease(ctx, req)
}

func (srv *securedServer) Report(ctx context.Context, req *registrypb.RegisterRequest) (*registrypb.RegisterResponse, error) {
	if err := srv.authorize(ctx); err != nil {
		return nil, err
	}
	return srv.underlying.Report(ctx, req)
}

func (srv *securedServer) ServerInfo(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ServerInfoResponse, error) {
	if err := srv.authorize(ctx); err != nil {
		return nil, err
	}
	return srv.underlying.ServerInfo(ctx, req)
}

func (srv *securedServer) SetCheckpoint(ctx context.Context, req *databrokerpb.Checkpoint) (*emptypb.Empty, error) {
	if err := srv.authorize(ctx); err != nil {
		return nil, err
	}
	return srv.underlying.SetCheckpoint(ctx, req)
}

func (srv *securedServer) SetOptions(ctx context.Context, req *databrokerpb.SetOptionsRequest) (*databrokerpb.SetOptionsResponse, error) {
	if err := srv.authorize(ctx); err != nil {
		return nil, err
	}
	return srv.underlying.SetOptions(ctx, req)
}

func (srv *securedServer) Sync(req *databrokerpb.SyncRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncResponse]) error {
	if err := srv.authorize(stream.Context()); err != nil {
		return err
	}
	return srv.underlying.Sync(req, stream)
}

func (srv *securedServer) SyncLatest(req *databrokerpb.SyncLatestRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncLatestResponse]) error {
	if err := srv.authorize(stream.Context()); err != nil {
		return err
	}
	return srv.underlying.SyncLatest(req, stream)
}

func (srv *securedServer) Watch(req *registrypb.ListRequest, stream grpc.ServerStreamingServer[registrypb.ServiceList]) error {
	if err := srv.authorize(stream.Context()); err != nil {
		return err
	}
	return srv.underlying.Watch(req, stream)
}

func (srv *securedServer) Stop() {
	srv.underlying.Stop()
}

func (srv *securedServer) OnConfigChange(ctx context.Context, cfg *config.Config) {
	srv.underlying.OnConfigChange(ctx, cfg)

	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("databroker: failed to load shared key")
		return
	}
	sharedKey = slices.Clone(sharedKey)
	srv.sharedKey.Store(&sharedKey)
}

func (srv *securedServer) authorize(ctx context.Context) error {
	sharedKey := srv.sharedKey.Load()
	if sharedKey == nil {
		return status.Error(codes.Unavailable, "no shared key defined")
	}
	return grpcutil.RequireSignedJWT(ctx, *sharedKey)
}
