package grpc

import (
	"context"

	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/pomerium/pomerium/internal/log"
)

type healthCheckSrv struct {
	grpc_health_v1.UnimplementedHealthServer
}

// NewHealthCheckServer returns a basic health checker
func NewHealthCheckServer() grpc_health_v1.HealthServer {
	return &healthCheckSrv{}
}

// Check confirms service is reachable, and assumes any service is operational
// an outlier detection should be used to detect runtime malfunction based on consequitive 5xx
func (h *healthCheckSrv) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	log.Ctx(ctx).Debug().Str("service", req.Service).Msg("health check")
	return &grpc_health_v1.HealthCheckResponse{
		Status: grpc_health_v1.HealthCheckResponse_SERVING,
	}, nil
}
