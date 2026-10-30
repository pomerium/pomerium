package envoy

import (
	"context"
	"errors"
	"fmt"

	"github.com/pomerium/pomerium/pkg/health"
	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
	"github.com/pomerium/pomerium/pkg/netutil"
)

var _ healthv2.ServiceEvaluator = (*Server)(nil)

type envoyProcess struct {
	adminAddress netutil.InternalAddress
	exited       chan struct{}
	extensions   []dynamicExtension
}

func (p *envoyProcess) running() error {
	if p == nil {
		return errors.New("envoy not started")
	}
	select {
	case <-p.exited:
		return errors.New("envoy process exited")
	default:
		return nil
	}
}

func (srv *Server) HealthCheckers() []healthv2.ServiceEvaluator {
	return []healthv2.ServiceEvaluator{srv, recordingHealthChecker{srv: srv}}
}

func (srv *Server) Service() healthv2.ServiceID {
	return healthv2.ServiceEnvoy
}

func (srv *Server) Component() string {
	return "process"
}

func (srv *Server) Initialized(ctx context.Context) (bool, healthv2.Info) {
	// TODO : health check v2
	return srv.Ready(ctx)
}

func (srv *Server) Ready(ctx context.Context) (bool, healthv2.Info) {
	p := srv.process.Load()
	if err := p.running(); err != nil {
		return false, healthv2.Info{Reason: err.Error()}
	}
	if err := envoyReady(ctx, p.adminAddress); err != nil {
		return false, healthv2.Info{Reason: err.Error()}
	}
	return srv.extensionsLoaded(ctx, p)
}

func (srv *Server) Healthy(ctx context.Context) (bool, healthv2.Info) {
	p := srv.process.Load()
	if err := p.running(); err != nil {
		return false, healthv2.Info{Reason: err.Error()}
	}
	if _, err := envoyReadyStatus(ctx, p.adminAddress); err != nil {
		return false, healthv2.Info{Reason: fmt.Sprintf("envoy admin unreachable: %s", err)}
	}
	return srv.extensionsLoaded(ctx, p)
}

func (srv *Server) OnShutdown(context.Context, error) {
	// TODO : health check v2
}

func (srv *Server) extensionsLoaded(ctx context.Context, p *envoyProcess) (bool, healthv2.Info) {
	if len(p.extensions) == 0 {
		return true, healthv2.Info{}
	}
	status, err := envoyDynamicExtStatus(ctx, p.adminAddress)
	if err != nil {
		return false, healthv2.Info{Reason: fmt.Sprintf("failed to check extension status: %s", err)}
	}
	_, attrs, err := srv.compareExtensions(p.extensions, status)
	info := healthv2.Info{Details: attrsToDetails(attrs)}
	if err != nil {
		info.Reason = err.Error()
		return false, info
	}
	return true, info
}

func attrsToDetails(attrs []health.Attr) map[string]string {
	details := make(map[string]string, len(attrs))
	for _, attr := range attrs {
		details[attr.Key] = attr.Value
	}
	return details
}
