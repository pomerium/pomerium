package sink

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
	"github.com/pomerium/pomerium/pkg/health/v2/check"
)

func running(name string, attrs ...check.Attr) check.Result {
	return check.Result{Name: check.CheckName(name), Status: check.StatusRunning, Attrs: attrs}
}

func terminating(name string) check.Result {
	return check.Result{Name: check.CheckName(name), Status: check.StatusTerminating}
}

func failing(name string, status check.Status, msg string) check.Result {
	return check.Result{Name: check.CheckName(name), Status: status, Err: errors.New(msg)}
}

func checkerStatus(group check.Group, name string, results ...check.Result) healthv2.CheckerStatus {
	return healthv2.CheckerStatus{Group: group, Name: name, Results: results}
}

func snapshotOf(results ...check.Result) healthv2.Snapshot {
	return healthv2.Snapshot{Configured: true, Checkers: []healthv2.CheckerStatus{checkerStatus("", "c", results...)}}
}

type testChecker struct {
	expected []check.CheckName
	results  atomic.Pointer[[]check.Result]
}

func newChecker(results ...check.Result) *testChecker {
	c := &testChecker{}
	for _, r := range results {
		c.expected = append(c.expected, r.Name)
	}
	c.set(results...)
	return c
}

func (c *testChecker) set(results ...check.Result) { c.results.Store(&results) }

func (c *testChecker) Group() check.Group { return "" }

func (c *testChecker) Name() string { return "c" }

func (c *testChecker) ConfigureChecks(*config.Options) []check.CheckName { return c.expected }

func (c *testChecker) Check(context.Context) []check.Result { return *c.results.Load() }

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return data
}

func runManager(t *testing.T, m *healthv2.Manager) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = m.Run(ctx)
	}()
	stop = func() {
		cancel()
		<-done
	}
	t.Cleanup(stop)
	return stop
}
