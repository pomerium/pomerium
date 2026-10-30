package databroker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/pomerium/pomerium/config"
	healthv2 "github.com/pomerium/pomerium/pkg/health/v2"
)

type stateCC struct {
	grpc.ClientConnInterface
	state connectivity.State
}

func (cc stateCC) GetState() connectivity.State { return cc.state }

type fixedServer struct {
	Server
	ok   bool
	info healthv2.Info
}

func (s fixedServer) Ready(context.Context) (bool, healthv2.Info)   { return s.ok, s.info }
func (s fixedServer) Healthy(context.Context) (bool, healthv2.Info) { return s.ok, s.info }

func newFixedServer(t *testing.T, ok bool) fixedServer {
	local := NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(local.Stop)
	return fixedServer{Server: local, ok: ok}
}

func unreachableLeader(t *testing.T) *grpc.ClientConn {
	cc, err := grpc.NewClient("127.0.0.1:1", grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	return cc
}

func TestForwardingServerHealth(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		state          connectivity.State
		ready, healthy bool
	}{
		{connectivity.Idle, true, true},
		{connectivity.Ready, true, true},
		{connectivity.Connecting, false, true},
		{connectivity.TransientFailure, false, true},
		{connectivity.Shutdown, false, false},
	} {
		t.Run(tc.state.String(), func(t *testing.T) {
			t.Parallel()
			srv := NewForwardingServer(stateCC{state: tc.state})
			ready, info := srv.Ready(t.Context())
			assert.Equal(t, tc.ready, ready)
			assert.Equal(t, tc.state.String(), info.Details["leader_conn"])
			healthy, _ := srv.Healthy(t.Context())
			assert.Equal(t, tc.healthy, healthy)
		})
	}
}

func TestClusteredLeaderServerHealth(t *testing.T) {
	t.Parallel()

	t.Run("nil_details", func(t *testing.T) {
		t.Parallel()
		srv := NewClusteredLeaderServer(newFixedServer(t, true))
		t.Cleanup(srv.Stop)
		ready, info := srv.Ready(t.Context())
		assert.True(t, ready)
		assert.Equal(t, "leader", info.Details["member"])
	})

	t.Run("stopped", func(t *testing.T) {
		t.Parallel()
		srv := NewClusteredLeaderServer(newFixedServer(t, true))
		srv.Stop()
		ready, _ := srv.Ready(t.Context())
		assert.False(t, ready)
		healthy, _ := srv.Healthy(t.Context())
		assert.False(t, healthy)
	})
}

func TestClusteredFollowerServerHealth(t *testing.T) {
	t.Parallel()

	t.Run("unreachable_leader", func(t *testing.T) {
		t.Parallel()
		srv := NewClusteredFollowerServer(noop.NewTracerProvider(), newFixedServer(t, true), unreachableLeader(t))
		t.Cleanup(srv.Stop)
		ready, info := srv.Ready(t.Context())
		assert.False(t, ready)
		assert.NotEmpty(t, info.Reason)
		assert.Equal(t, "follower", info.Details["member"])
		healthy, _ := srv.Healthy(t.Context())
		assert.True(t, healthy)
	})

	t.Run("stop_after_check", func(t *testing.T) {
		t.Parallel()
		srv := NewClusteredFollowerServer(noop.NewTracerProvider(), newFixedServer(t, true), unreachableLeader(t)).(*clusteredFollowerServer)
		srv.cancel(nil)
		require.Eventually(t, func() bool {
			healthy, _ := srv.Healthy(t.Context())
			return !healthy
		}, 5*time.Second, time.Millisecond)

		stopped := make(chan struct{})
		go func() {
			srv.Stop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			assert.Fail(t, "Stop blocked after a health check")
		}
	})
}

func TestClusteredServerHealth(t *testing.T) {
	t.Parallel()

	srv := NewClusteredServer(noop.NewTracerProvider(), newFixedServer(t, true), &config.Config{Options: config.NewDefaultOptions()})
	t.Cleanup(srv.Stop)
	ready, _ := srv.Ready(t.Context())
	assert.True(t, ready)

	srv.(*clusteredServer).mu.Lock()
	srv.(*clusteredServer).currentServer = NewErroringServer(errors.New("boom"))
	srv.(*clusteredServer).mu.Unlock()
	ready, info := srv.Ready(t.Context())
	assert.False(t, ready)
	assert.Equal(t, "boom", info.Reason)
}

func TestBackendServerHealth(t *testing.T) {
	t.Parallel()

	t.Run("in_memory", func(t *testing.T) {
		t.Parallel()
		srv := NewBackendServer(noop.NewTracerProvider())
		t.Cleanup(srv.Stop)
		ready, info := srv.Ready(t.Context())
		assert.True(t, ready)
		assert.Equal(t, "memory", info.Details["storage"])
		healthy, _ := srv.Healthy(t.Context())
		assert.True(t, healthy)
	})

	t.Run("stopped", func(t *testing.T) {
		t.Parallel()
		srv := NewBackendServer(noop.NewTracerProvider()).(*backendServer)
		srv.Stop()
		ready, _ := srv.Ready(t.Context())
		assert.False(t, ready)
		srv.mu.RLock()
		assert.Nil(t, srv.backend)
		srv.mu.RUnlock()
	})
}
