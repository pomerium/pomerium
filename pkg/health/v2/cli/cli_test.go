package cli

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
	"github.com/pomerium/pomerium/pkg/health/v2/sink"
)

func TestCLI(t *testing.T) {
	t.Parallel()

	ok := healthv2.Condition{OK: true}
	failed := healthv2.Condition{Info: healthv2.Info{Reason: "boom"}}
	status := func(name string, initialized, ready, healthy healthv2.Condition) healthv2.CheckerStatus {
		return healthv2.CheckerStatus{Service: healthv2.ServiceProxy, Name: name, Initialized: initialized, Ready: ready, Healthy: healthy}
	}

	for _, tc := range []struct {
		name    string
		snap    healthv2.Snapshot
		exclude []string
		healthy bool
	}{
		{
			name:    "ok",
			snap:    healthv2.Snapshot{Checkers: []healthv2.CheckerStatus{status("a", ok, ok, ok)}},
			healthy: true,
		},
		{
			name:    "not_ready",
			snap:    healthv2.Snapshot{Checkers: []healthv2.CheckerStatus{status("a", ok, failed, ok)}},
			healthy: true,
		},
		{
			name: "starting",
			snap: healthv2.Snapshot{Checkers: []healthv2.CheckerStatus{status("a", failed, failed, ok)}},
		},
		{
			name: "unhealthy",
			snap: healthv2.Snapshot{Checkers: []healthv2.CheckerStatus{status("a", ok, ok, failed)}},
		},
		{
			name: "excluded",
			snap: healthv2.Snapshot{Checkers: []healthv2.CheckerStatus{
				status("a", ok, ok, ok),
				status("b", ok, ok, failed),
			}},
			exclude: []string{"Proxy/b"},
			healthy: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := sink.NewHTTP()
			h.Notify(tc.snap)
			server := httptest.NewServer(http.HandlerFunc(h.Status))
			t.Cleanup(server.Close)

			req, err := http.NewRequest(http.MethodGet, server.URL+"/status", nil)
			require.NoError(t, err)
			_, err = getHTTPStatus(server.Client(), req, tc.exclude)
			if tc.healthy {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, ErrUnhealthy)
			}
		})
	}
}
