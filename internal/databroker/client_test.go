package databroker_test

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func TestOnFinish(t *testing.T) {
	t.Parallel()

	li, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = li.Close() })

	srv := grpc.NewServer()
	hsrv := health.NewServer()
	grpc_health_v1.RegisterHealthServer(srv, hsrv)
	hsrv.SetServingStatus("test", grpc_health_v1.HealthCheckResponse_SERVING)
	go srv.Serve(li)

	cc, err := grpc.NewClient(li.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithIdleTimeout(time.Second))
	require.NoError(t, err)

	res, err := grpc_health_v1.NewHealthClient(cc).Check(t.Context(), &grpc_health_v1.HealthCheckRequest{
		Service: "test",
	})
	assert.NoError(t, err)
	assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, res.GetStatus())

	assert.True(t, cc.WaitForStateChange(t.Context(), connectivity.Idle))
	assert.Equal(t, connectivity.Ready, cc.GetState())
	assert.True(t, cc.WaitForStateChange(t.Context(), connectivity.Ready))
	assert.Equal(t, connectivity.Idle, cc.GetState())
}
