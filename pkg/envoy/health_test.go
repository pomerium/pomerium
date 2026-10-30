package envoy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServerHealthProcess(t *testing.T) {
	t.Parallel()

	exited := make(chan struct{})
	close(exited)

	for _, tc := range []struct {
		name    string
		process *envoyProcess
		reason  string
	}{
		{"not_started", nil, "envoy not started"},
		{"exited", &envoyProcess{exited: exited}, "envoy process exited"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := &Server{}
			srv.process.Store(tc.process)

			ready, info := srv.Ready(t.Context())
			assert.False(t, ready)
			assert.Equal(t, tc.reason, info.Reason)
			healthy, info := srv.Healthy(t.Context())
			assert.False(t, healthy)
			assert.Equal(t, tc.reason, info.Reason)
		})
	}
}
