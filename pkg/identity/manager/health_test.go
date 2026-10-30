package manager

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestManagerHealth(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name            string
		running, leased bool
		ok              bool
		lease           string
	}{
		{"stopped", false, false, false, "standby"},
		{"standby", true, false, true, "standby"},
		{"leased", true, true, true, "held"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mgr := &Manager{}
			mgr.running.Store(tc.running)
			mgr.leased.Store(tc.leased)

			ready, info := mgr.Ready(t.Context())
			assert.Equal(t, tc.ok, ready)
			assert.Equal(t, tc.lease, info.Details["lease"])
			healthy, _ := mgr.Healthy(t.Context())
			assert.Equal(t, tc.ok, healthy)
		})
	}
}
