package cache

import (
	"context"

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/internal/grpc/databroker"
	"github.com/pomerium/pomerium/internal/grpc/session"
	"github.com/pomerium/pomerium/internal/log"
)

// SessionServer implements the session service interface for adding and syncing sessions.
type SessionServer struct {
	dataBrokerClient databroker.DataBrokerServiceClient
}

// NewSessionServer creates a new SessionServer.
func NewSessionServer(grpcServer *grpc.Server, dataBrokerClient databroker.DataBrokerServiceClient) *SessionServer {
	srv := &SessionServer{
		dataBrokerClient: dataBrokerClient,
	}
	session.RegisterSessionServiceServer(grpcServer, srv)
	return srv
}

// Delete deletes a session from the session server.
func (srv *SessionServer) Delete(ctx context.Context, req *session.DeleteRequest) (*emptypb.Empty, error) {
	log.Info().
		Str("service", "session").
		Str("session_id", req.GetId()).
		Msg("delete")

	data, err := ptypes.MarshalAny(new(session.Session))
	if err != nil {
		return nil, err
	}

	return srv.dataBrokerClient.Delete(ctx, &databroker.DeleteRequest{
		Type: data.GetTypeUrl(),
		Id:   req.GetId(),
	})
}

// Add adds a session to the session server.
func (srv *SessionServer) Add(ctx context.Context, req *session.AddRequest) (*session.AddResponse, error) {
	log.Info().
		Str("service", "session").
		Str("session_id", req.GetSession().GetId()).
		Msg("add")

	data, err := ptypes.MarshalAny(req.GetSession())
	if err != nil {
		return nil, err
	}

	res, err := srv.dataBrokerClient.Set(ctx, &databroker.SetRequest{
		Type: data.GetTypeUrl(),
		Id:   req.GetSession().GetId(),
		Data: data,
	})
	if err != nil {
		return nil, err
	}

	return &session.AddResponse{
		Session:       req.Session,
		ServerVersion: res.GetServerVersion(),
	}, nil
}
