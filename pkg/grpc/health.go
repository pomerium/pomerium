package grpc

import (
	"context"

	"google.golang.org/grpc/codes"
	grpc_health "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/log"
)

type healthCheckSrv struct{}

// NewHealthCheckServer returns a basic health checker
func NewHealthCheckServer() grpc_health.HealthServer {
	return &healthCheckSrv{}
}

// Check confirms service is reachable, and assumes any service is operational
// an outlier detection should be used to detect runtime malfunction based on consequitive 5xx
func (h *healthCheckSrv) Check(ctx context.Context, req *grpc_health.HealthCheckRequest) (*grpc_health.HealthCheckResponse, error) {
	log.Debug(ctx).Str("service", req.Service).Msg("health check")
	return &grpc_health.HealthCheckResponse{
		Status: grpc_health.HealthCheckResponse_SERVING,
	}, nil
}

// Watch is not implemented as is not used by Envoy
func (h *healthCheckSrv) Watch(req *grpc_health.HealthCheckRequest, _ grpc_health.Health_WatchServer) error {
	log.Error().Str("service", req.Service).Msg("health check watch")
	return status.Errorf(codes.Unimplemented, "method Watch not implemented")
}
