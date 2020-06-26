package cache

import (
	"context"

	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
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
	ctx, span := trace.StartSpan(ctx, "session.grpc.Delete")
	defer span.End()
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
	ctx, span := trace.StartSpan(ctx, "session.grpc.Add")
	defer span.End()
	log.Info().
		Str("service", "session").
		Str("session_id", req.GetSession().GetId()).
		Msg("add")

	s := req.GetSession()

	data, err := ptypes.MarshalAny(s)
	if err != nil {
		return nil, err
	}

	res, err := srv.dataBrokerClient.Set(ctx, &databroker.SetRequest{
		Type: data.GetTypeUrl(),
		Id:   s.GetId(),
		Data: data,
	})
	if err != nil {
		return nil, err
	}

	s.Version = res.GetServerVersion()

	data, err = ptypes.MarshalAny(s)
	if err != nil {
		return nil, err
	}

	res, err = srv.dataBrokerClient.Set(ctx, &databroker.SetRequest{
		Type: data.GetTypeUrl(),
		Id:   s.GetId(),
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
