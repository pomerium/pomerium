package cache

import (
	"github.com/golang/protobuf/ptypes"

	"github.com/pomerium/pomerium/internal/grpc/databroker"
	"github.com/pomerium/pomerium/internal/grpc/user"
)

// UserServer implements the user service interface for syncing users.
type UserServer struct {
	dataBrokerClient databroker.DataBrokerServiceClient
}

// NewUserServer creates a new UserServer.
func NewUserServer(dataBrokerClient databroker.DataBrokerServiceClient) *UserServer {
	return &UserServer{
		dataBrokerClient: dataBrokerClient,
	}
}

// Sync syncs users from the UserServer.
func (srv *UserServer) Sync(req *user.SyncRequest, stream user.UserService_SyncServer) error {
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
