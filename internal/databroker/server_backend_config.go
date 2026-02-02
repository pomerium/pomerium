package databroker

import (
	"context"

	"connectrpc.com/connect"

	"github.com/pomerium/pomerium/internal/version"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/config/configconnect"
)

type backendConfigServer struct {
	*backendServer

	configconnect.UnimplementedConfigServiceHandler
}

func (srv *backendConfigServer) GetServerInfo(
	_ context.Context,
	_ *connect.Request[configpb.GetServerInfoRequest],
) (*connect.Response[configpb.GetServerInfoResponse], error) {
	return connect.NewResponse(&configpb.GetServerInfoResponse{
		ServerType: configpb.ServerType_SERVER_TYPE_CORE,
		Version:    version.FullVersion(),
	}), nil
}
