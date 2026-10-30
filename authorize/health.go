package authorize

import (
	"context"

	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
)

var _ healthv2.ServiceEvaluator = (*Authorize)(nil)

func (a *Authorize) HealthCheckers() []healthv2.ServiceEvaluator {
	return []healthv2.ServiceEvaluator{a, a.ssh}
}

func (a *Authorize) Service() healthv2.ServiceID {
	return healthv2.ServiceAuthorize
}

func (a *Authorize) Component() string {
	return "server"
}

func (a *Authorize) Initialized(ctx context.Context) (bool, healthv2.Info) {
	if !a.running.Load() {
		return false, healthv2.Info{Reason: "authorize not running"}
	}
	started, info := a.databrokerEvaluator().Initialized(ctx)
	if !started {
		info.Reason = "databroker not initialized"
	}
	return started, info
}

func (a *Authorize) Ready(ctx context.Context) (bool, healthv2.Info) {
	if a.shutdownRequested.Load() {
		return false, healthv2.Info{Reason: "shutdown requested"}
	}
	if !a.running.Load() {
		return false, healthv2.Info{Reason: "authorize not running"}
	}
	ready, info := a.databrokerEvaluator().Ready(ctx)
	if !ready {
		info.Reason = "databroker connection not ready"
	}
	return ready, info
}

func (a *Authorize) Healthy(ctx context.Context) (bool, healthv2.Info) {
	healthy, info := a.healthy(ctx)
	if a.shutdownRequested.Load() {
		return !healthy, info
	}
	return healthy, info
}

func (a *Authorize) healthy(ctx context.Context) (bool, healthv2.Info) {
	if !a.running.Load() {
		return false, healthv2.Info{Reason: "authorize not running"}
	}
	healthy, info := a.databrokerEvaluator().Healthy(ctx)
	if !healthy {
		info.Reason = "databroker connection closed"
	}
	return healthy, info
}

func (a *Authorize) OnShutdown(context.Context, error) {
	a.shutdownRequested.Store(true)
}

func (a *Authorize) databrokerEvaluator() healthv2.Evaluator {
	return healthv2.NewGrpcCCEvaluator(a.state.Load().dataBrokerClientConnection)
}
