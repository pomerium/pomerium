package envoy

import (
	"context"

	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
)

// recordingHealthChecker is ready and healthy while no recording server
// exists, and delegates to the current one otherwise.
type recordingHealthChecker struct {
	srv *Server
}

var _ healthv2.ServiceEvaluator = recordingHealthChecker{}

func (recordingHealthChecker) Service() healthv2.ServiceID {
	// this currently only makes sense as part of Authorize,
	// since we don't implement gRPC protocols in envoy - only
	// unix pipes.
	// In the future, this could either be split out
	// in its own group or part of a ControlPlane group.
	return healthv2.ServiceAuthorize
}

func (recordingHealthChecker) Component() string { return "recording" }

func (c recordingHealthChecker) Initialized(ctx context.Context) (bool, healthv2.Info) {
	// TODO : health check v2
	return c.Ready(ctx)
}

func (c recordingHealthChecker) Ready(ctx context.Context) (bool, healthv2.Info) {
	recSrv := c.srv.recordingServer.Load()
	if recSrv == nil {
		return true, healthv2.Info{}
	}
	return (*recSrv).Ready(ctx)
}

func (c recordingHealthChecker) Healthy(ctx context.Context) (bool, healthv2.Info) {
	recSrv := c.srv.recordingServer.Load()
	if recSrv == nil {
		return true, healthv2.Info{}
	}
	return (*recSrv).Healthy(ctx)
}

func (c recordingHealthChecker) OnShutdown(context.Context, error) {
	// TODO : health check v2
}
