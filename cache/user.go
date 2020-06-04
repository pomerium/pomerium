package cache

import (
	"context"

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/internal/grpc/databroker"
	"github.com/pomerium/pomerium/internal/grpc/user"
	"github.com/pomerium/pomerium/internal/log"
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

// Sync syncs users from the UserServer.
func (srv *UserServer) Sync(req *user.SyncRequest, stream user.UserService_SyncServer) error {
	log.Info().
		Str("service", "user").
		Str("server_version", req.GetServerVersion()).
		Str("record_version", req.GetRecordVersion()).
		Msg("sync")

	data, err := ptypes.MarshalAny(new(user.User))
	if err != nil {
		return err
	}

	client, err := srv.dataBrokerClient.Sync(stream.Context(), &databroker.SyncRequest{
		ServerVersion: req.GetServerVersion(),
		RecordVersion: req.GetRecordVersion(),
		Type:          data.GetTypeUrl(),
	})
	if err != nil {
		return err
	}

	for {
		res, err := client.Recv()
		if err != nil {
			return err
		}

		users := make([]*user.User, 0, len(res.GetRecords()))
		for _, record := range res.GetRecords() {
			var u user.User
			err = ptypes.UnmarshalAny(record.GetData(), &u)
			if err != nil {
				return err
			}
			users = append(users, &u)
		}

		err = stream.Send(&user.SyncResponse{
			ServerVersion: res.GetServerVersion(),
			Users:         users,
		})
		if err != nil {
			return err
		}
	}
}
