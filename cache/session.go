package cache

import (
	"context"

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/internal/grpc/databroker"
	"github.com/pomerium/pomerium/internal/grpc/session"
)

// SessionServer implements the session service interface for adding and syncing sessions.
type SessionServer struct {
	dataBrokerClient databroker.DataBrokerServiceClient
}

// NewSessionServer creates a new SessionServer.
func NewSessionServer(dataBrokerClient databroker.DataBrokerServiceClient) *SessionServer {
	return &SessionServer{
		dataBrokerClient: dataBrokerClient,
	}
}

// Add adds a session to the session server.
func (srv *SessionServer) Add(ctx context.Context, req *session.AddRequest) (*emptypb.Empty, error) {
	data, err := ptypes.MarshalAny(req.GetSession())
	if err != nil {
		return nil, err
	}

	_, err = srv.dataBrokerClient.Set(ctx, &databroker.SetRequest{
		Type: data.GetTypeUrl(),
		Id:   req.GetSession().GetId(),
		Data: data,
	})
	if err != nil {
		return nil, err
	}

	return new(emptypb.Empty), nil
}

// Sync sync sessions from the session server.
func (srv *SessionServer) Sync(req *session.SyncRequest, stream session.SessionService_SyncServer) error {
	data, err := ptypes.MarshalAny(new(session.Session))
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

		sessions := make([]*session.Session, 0, len(res.GetRecords()))
		for _, record := range res.GetRecords() {
			var s session.Session
			err = ptypes.UnmarshalAny(record.Data, &s)
			if err != nil {
				return err
			}
		}

		err = stream.Send(&session.SyncResponse{
			ServerVersion: res.GetServerVersion(),
			Sessions:      sessions,
		})
		if err != nil {
			return err
		}
	}
}
