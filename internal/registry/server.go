package registry

import (
	"time"

	pb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

func NewServer() (pb.RegistryServer, error) {
	return &inMemoryServer{ttl: time.Second}, nil
}
