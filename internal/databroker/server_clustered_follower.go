package databroker

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

type clusteredFollowerServer struct {
	leader Server
	local  Server
}

// NewClusteredFollowerServer creates a new clustered follower databroker
// server. A clustered follower server forwards all requests to a leader
// databroker via the passed client connection.
func NewClusteredFollowerServer(local Server, leaderCC grpc.ClientConnInterface) Server {
	srv := &clusteredFollowerServer{
		leader: NewForwardingServer(leaderCC),
		local:  local,
	}
	return srv
}

func (srv *clusteredFollowerServer) AcquireLease(ctx context.Context, req *databrokerpb.AcquireLeaseRequest) (res *databrokerpb.AcquireLeaseResponse, err error) {
	return res, srv.invokeReadWrite(ctx, func(handler Server) error {
		var err error
		res, err = handler.AcquireLease(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Clear(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ClearResponse, err error) {
	return res, srv.invokeReadWrite(ctx, func(handler Server) error {
		var err error
		res, err = handler.Clear(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Get(ctx context.Context, req *databrokerpb.GetRequest) (res *databrokerpb.GetResponse, err error) {
	return res, srv.invokeReadOnly(ctx, func(handler Server) error {
		var err error
		res, err = handler.Get(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) List(ctx context.Context, req *registrypb.ListRequest) (res *registrypb.ServiceList, err error) {
	return res, srv.invokeReadOnly(ctx, func(handler Server) error {
		var err error
		res, err = handler.List(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) ListTypes(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ListTypesResponse, err error) {
	return res, srv.invokeReadOnly(ctx, func(handler Server) error {
		var err error
		res, err = handler.ListTypes(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Patch(ctx context.Context, req *databrokerpb.PatchRequest) (res *databrokerpb.PatchResponse, err error) {
	return res, srv.invokeReadWrite(ctx, func(handler Server) error {
		var err error
		res, err = handler.Patch(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Put(ctx context.Context, req *databrokerpb.PutRequest) (res *databrokerpb.PutResponse, err error) {
	return res, srv.invokeReadWrite(ctx, func(handler Server) error {
		var err error
		res, err = handler.Put(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Query(ctx context.Context, req *databrokerpb.QueryRequest) (res *databrokerpb.QueryResponse, err error) {
	return res, srv.invokeReadOnly(ctx, func(handler Server) error {
		var err error
		res, err = handler.Query(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) ReleaseLease(ctx context.Context, req *databrokerpb.ReleaseLeaseRequest) (res *emptypb.Empty, err error) {
	return res, srv.invokeReadWrite(ctx, func(handler Server) error {
		var err error
		res, err = handler.ReleaseLease(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) RenewLease(ctx context.Context, req *databrokerpb.RenewLeaseRequest) (res *emptypb.Empty, err error) {
	return res, srv.invokeReadWrite(ctx, func(handler Server) error {
		var err error
		res, err = handler.RenewLease(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Report(ctx context.Context, req *registrypb.RegisterRequest) (res *registrypb.RegisterResponse, err error) {
	return res, srv.invokeReadWrite(ctx, func(handler Server) error {
		var err error
		res, err = handler.Report(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) ServerInfo(ctx context.Context, req *emptypb.Empty) (res *databrokerpb.ServerInfoResponse, err error) {
	return res, srv.invokeReadOnly(ctx, func(handler Server) error {
		var err error
		res, err = handler.ServerInfo(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) SetOptions(ctx context.Context, req *databrokerpb.SetOptionsRequest) (res *databrokerpb.SetOptionsResponse, err error) {
	return res, srv.invokeReadWrite(ctx, func(handler Server) error {
		var err error
		res, err = handler.SetOptions(ctx, req)
		return err
	})
}

func (srv *clusteredFollowerServer) Sync(req *databrokerpb.SyncRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncResponse]) error {
	return srv.invokeReadOnly(stream.Context(), func(handler Server) error {
		return handler.Sync(req, stream)
	})
}

func (srv *clusteredFollowerServer) SyncLatest(req *databrokerpb.SyncLatestRequest, stream grpc.ServerStreamingServer[databrokerpb.SyncLatestResponse]) error {
	return srv.invokeReadOnly(stream.Context(), func(handler Server) error {
		return handler.SyncLatest(req, stream)
	})
}

func (srv *clusteredFollowerServer) Watch(req *registrypb.ListRequest, stream grpc.ServerStreamingServer[registrypb.ServiceList]) error {
	return srv.invokeReadOnly(stream.Context(), func(handler Server) error {
		return handler.Watch(req, stream)
	})
}

func (srv *clusteredFollowerServer) Stop()                                              {}
func (srv *clusteredFollowerServer) OnConfigChange(_ context.Context, _ *config.Config) {}

func (srv *clusteredFollowerServer) invokeReadOnly(ctx context.Context, fn func(handler Server) error) error {
	switch databrokerpb.GetIncomingClusterRequestMode(ctx) {
	case databrokerpb.ClusterRequestModeDefault:
		// forward to leader
		return fn(srv.leader)
	case databrokerpb.ClusterRequestModeLeader:
		// not a leader, so error out
		return databrokerpb.ErrNodeIsNotLeader
	case databrokerpb.ClusterRequestModeLocal:
		// send to local
		return fn(srv.local)
	default:
		return databrokerpb.ErrUnknownClusterRequestMode
	}
}

func (srv *clusteredFollowerServer) invokeReadWrite(ctx context.Context, fn func(handler Server) error) error {
	switch databrokerpb.GetIncomingClusterRequestMode(ctx) {
	case databrokerpb.ClusterRequestModeDefault:
		// forward to leader
		return fn(srv.leader)
	case databrokerpb.ClusterRequestModeLeader:
		// not a leader, so error out
		return databrokerpb.ErrNodeIsNotLeader
	case databrokerpb.ClusterRequestModeLocal:
		// not a leader and it's not safe to modify the local, so error out
		return databrokerpb.ErrNodeIsNotLeader
	default:
		return databrokerpb.ErrUnknownClusterRequestMode
	}
}
