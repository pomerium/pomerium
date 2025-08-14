package databroker

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

func (srv *server) AcquireLease(ctx context.Context, req *databrokerpb.AcquireLeaseRequest) (*databrokerpb.AcquireLeaseResponse, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load()); err != nil {
		return nil, err
	}
	return srv.server.AcquireLease(ctx, req)
}

func (srv *server) Get(ctx context.Context, req *databrokerpb.GetRequest) (*databrokerpb.GetResponse, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load()); err != nil {
		return nil, err
	}
	return srv.server.Get(ctx, req)
}

func (srv *server) ListTypes(ctx context.Context, req *emptypb.Empty) (*databrokerpb.ListTypesResponse, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load()); err != nil {
		return nil, err
	}
	return srv.server.ListTypes(ctx, req)
}

func (srv *server) Patch(ctx context.Context, req *databrokerpb.PatchRequest) (*databrokerpb.PatchResponse, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load()); err != nil {
		return nil, err
	}
	return srv.server.Patch(ctx, req)
}

func (srv *server) Put(ctx context.Context, req *databrokerpb.PutRequest) (*databrokerpb.PutResponse, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load()); err != nil {
		return nil, err
	}
	return srv.server.Put(ctx, req)
}

func (srv *server) Query(ctx context.Context, req *databrokerpb.QueryRequest) (*databrokerpb.QueryResponse, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load()); err != nil {
		return nil, err
	}
	return srv.server.Query(ctx, req)
}

func (srv *server) ReleaseLease(ctx context.Context, req *databrokerpb.ReleaseLeaseRequest) (*emptypb.Empty, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load()); err != nil {
		return nil, err
	}
	return srv.server.ReleaseLease(ctx, req)
}

func (srv *server) RenewLease(ctx context.Context, req *databrokerpb.RenewLeaseRequest) (*emptypb.Empty, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load()); err != nil {
		return nil, err
	}
	return srv.server.RenewLease(ctx, req)
}

func (srv *server) SetOptions(ctx context.Context, req *databrokerpb.SetOptionsRequest) (*databrokerpb.SetOptionsResponse, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load()); err != nil {
		return nil, err
	}
	return srv.server.SetOptions(ctx, req)
}

func (srv *server) Sync(req *databrokerpb.SyncRequest, stream databrokerpb.DataBrokerService_SyncServer) error {
	if err := grpcutil.RequireSignedJWT(stream.Context(), srv.sharedKey.Load()); err != nil {
		return err
	}
	return srv.server.Sync(req, stream)
}

func (srv *server) SyncLatest(req *databrokerpb.SyncLatestRequest, stream databrokerpb.DataBrokerService_SyncLatestServer) error {
	if err := grpcutil.RequireSignedJWT(stream.Context(), srv.sharedKey.Load()); err != nil {
		return err
	}
	return srv.server.SyncLatest(req, stream)
}
