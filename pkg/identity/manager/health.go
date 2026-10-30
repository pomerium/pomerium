package manager

import (
	"context"

	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
)

var _ healthv2.ServiceEvaluator = (*Manager)(nil)

func (mgr *Manager) Service() healthv2.ServiceID {
	// this runs as a lease on the databroker
	return healthv2.ServiceDataBroker
}

func (mgr *Manager) Component() string {
	return "identity"
}

func (mgr *Manager) Initialized(context.Context) (bool, healthv2.Info) {
	return true, healthv2.Info{}
}

func (mgr *Manager) Ready(context.Context) (bool, healthv2.Info) {
	if mgr.shutdownRequested.Load() {
		return false, healthv2.Info{}
	}
	return mgr.healthCheck()
}

func (mgr *Manager) Healthy(context.Context) (bool, healthv2.Info) {
	if mgr.shutdownRequested.Load() {
		running, info := mgr.healthCheck()
		return !running, info

	}
	return mgr.healthCheck()
}

func (mgr *Manager) OnShutdown(context.Context, error) {
	mgr.shutdownRequested.Store(true)
}

func (mgr *Manager) healthCheck() (bool, healthv2.Info) {
	info := healthv2.Info{Details: map[string]string{"lease": mgr.leaseState()}}
	if !mgr.running.Load() {
		info.Reason = "identity manager not running"
		return false, info
	}
	return true, info
}

func (mgr *Manager) leaseState() string {
	if mgr.leased.Load() {
		return "held"
	}
	return "standby"
}
