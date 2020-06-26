package cache

import (
	"context"

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

// UserServer implements the user service interface for syncing users.
type UserServer struct {
	dataBrokerClient databroker.DataBrokerServiceClient
}

// NewUserServer creates a new UserServer.
func NewUserServer(grpcServer *grpc.Server, dataBrokerClient databroker.DataBrokerServiceClient) *UserServer {
	srv := &UserServer{
		dataBrokerClient: dataBrokerClient,
	}
	user.RegisterUserServiceServer(grpcServer, srv)
	return srv
}

// Add adds a user to the user server.
func (srv *UserServer) Add(ctx context.Context, req *user.AddRequest) (*emptypb.Empty, error) {
	ctx, span := trace.StartSpan(ctx, "user.grpc.Add")
	defer span.End()
	log.Info().
		Str("service", "user").
		Str("user_id", req.GetUser().GetId()).
		Msg("add")

	data, err := ptypes.MarshalAny(req.GetUser())
	if err != nil {
		return nil, err
	}

	_, err = srv.dataBrokerClient.Set(ctx, &databroker.SetRequest{
		Type: data.GetTypeUrl(),
		Id:   req.GetUser().GetId(),
		Data: data,
	})
	if err != nil {
		return nil, err
	}

	return new(emptypb.Empty), nil
}
