package registry

import (
	"context"
	"time"

	pb "github.com/pomerium/pomerium/pkg/grpc/registry"

	"github.com/golang/protobuf/ptypes"
)

type inMemoryServer struct {
	ttl time.Duration
}

// Report is periodically sent by each service to confirm it is still serving with the registry
// data is persisted with a certain TTL
func (s *inMemoryServer) Report(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	return &pb.RegisterResponse{
		CallBackAfter: ptypes.DurationProto(s.ttl),
	}, nil
}

// List returns current snapshot of the services known to the registry
func (s *inMemoryServer) List(context.Context, *pb.ListRequest) (*pb.ListResponse, error) {
	return &pb.ListResponse{}, nil
}

// Watch returns a stream of updates
// for the simplicity of consumer its delivered as full snapshots
func (s *inMemoryServer) Watch(req *pb.ListRequest, srv pb.Registry_WatchServer) error {
	ctx := srv.Context()

	select {
	case <-ctx.Done():
		return nil
	default:
		return nil
	}
}
