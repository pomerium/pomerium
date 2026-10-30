package sink

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
)

func pass(details map[string]string) healthv2.Condition {
	return healthv2.Condition{OK: true, Info: healthv2.Info{Details: details}}
}

func fail(reason string) healthv2.Condition {
	return healthv2.Condition{Info: healthv2.Info{Reason: reason}}
}

func checkerStatus(name string, ready, healthy healthv2.Condition) healthv2.CheckerStatus {
	return healthv2.CheckerStatus{Service: healthv2.ServiceProxy, Name: name, Initialized: pass(nil), Ready: ready, Healthy: healthy}
}

func uninitialized(c healthv2.CheckerStatus, reason string) healthv2.CheckerStatus {
	c.Initialized = fail(reason)
	c.Ready = fail(reason)
	return c
}

func running(name string) healthv2.CheckerStatus {
	return checkerStatus(name, pass(nil), pass(nil))
}

func snapshotOf(checkers ...healthv2.CheckerStatus) healthv2.Snapshot {
	return healthv2.Snapshot{Checkers: checkers}
}

type testChecker struct {
	name    string
	ready   atomic.Pointer[healthv2.Condition]
	healthy atomic.Pointer[healthv2.Condition]
}

func newChecker(name string) *testChecker {
	c := &testChecker{name: name}
	c.set(pass(nil), pass(nil))
	return c
}

func (c *testChecker) set(ready, healthy healthv2.Condition) {
	c.ready.Store(&ready)
	c.healthy.Store(&healthy)
}

func (c *testChecker) Service() healthv2.ServiceID { return healthv2.ServiceProxy }

func (c *testChecker) Component() string { return c.name }

func (c *testChecker) Initialized(context.Context) (bool, healthv2.Info) {
	return true, healthv2.Info{}
}

func (c *testChecker) Ready(context.Context) (bool, healthv2.Info) {
	r := c.ready.Load()
	return r.OK, r.Info
}

func (c *testChecker) Healthy(context.Context) (bool, healthv2.Info) {
	h := c.healthy.Load()
	return h.OK, h.Info
}

func (c *testChecker) OnShutdown(context.Context, error) {
	// TODO : health check v2
}

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return data
}

func runManager(t *testing.T, m *healthv2.Manager) {
	t.Helper()
	go m.Run(t.Context())
}
