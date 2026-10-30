package ssh

import (
	"context"

	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
)

var _ healthv2.ServiceEvaluator = (*StreamManager)(nil)

func (sm *StreamManager) Component() string {
	return "ssh"
}

func (sm *StreamManager) Service() healthv2.ServiceID {
	return healthv2.ServiceAuthorize
}

func (sm *StreamManager) initialSyncDone() bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.initialSessionSyncDone && sm.initialSessionBindingSyncDone
}

func (sm *StreamManager) Initialized(ctx context.Context) (bool, healthv2.Info) {
	// TODO : health check v2
	return sm.Ready(ctx)
}

func (sm *StreamManager) Ready(context.Context) (bool, healthv2.Info) {
	if !sm.sshEnabled.Load() {
		return true, healthv2.Info{}
	}
	if !sm.running.Load() {
		return false, healthv2.Info{Reason: "ssh stream manager not running"}
	}
	if !sm.initialSyncDone() {
		return false, healthv2.Info{Reason: "initial session sync in progress"}
	}
	return true, healthv2.Info{}
}

func (sm *StreamManager) Healthy(context.Context) (bool, healthv2.Info) {
	if !sm.sshEnabled.Load() {
		return true, healthv2.Info{}
	}
	if !sm.running.Load() {
		return false, healthv2.Info{Reason: "ssh stream manager not running"}
	}
	return true, healthv2.Info{}
}

func (sm *StreamManager) OnShutdown(context.Context, error) {
	// TODO : health check v2
}
