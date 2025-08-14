package databroker

import (
	"context"

	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

func (srv *server) List(ctx context.Context, req *registrypb.ListRequest) (*registrypb.ServiceList, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load()); err != nil {
		return nil, err
	}
	return srv.server.List(ctx, req)
}

func (srv *server) Report(ctx context.Context, req *registrypb.RegisterRequest) (*registrypb.RegisterResponse, error) {
	if err := grpcutil.RequireSignedJWT(ctx, srv.sharedKey.Load()); err != nil {
		return nil, err
	}
	return srv.server.Report(ctx, req)
}

func (srv *server) Watch(req *registrypb.ListRequest, stream registrypb.Registry_WatchServer) error {
	if err := grpcutil.RequireSignedJWT(stream.Context(), srv.sharedKey.Load()); err != nil {
		return err
	}
	return srv.server.Watch(req, stream)
}
