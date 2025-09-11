package grpcutil_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/pomerium/pomerium/pkg/grpcutil"
)

func TestClientManager(t *testing.T) {
	t.Parallel()

	li, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = li.Close() })

	s := grpc.NewServer()
	hsrv := health.NewServer()
	hsrv.SetServingStatus("test", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(s, hsrv)
	go s.Serve(li)

	mgr := grpcutil.NewClientManager(noop.NewTracerProvider(),
		grpcutil.WithClientManagerIdleTimeout(100*time.Millisecond),
		grpcutil.WithClientManagerNewClient(func(target string, options ...grpc.DialOption) (*grpc.ClientConn, error) {
			return grpc.NewClient(target, append(options, grpc.WithTransportCredentials(insecure.NewCredentials()))...)
		}),
	)
	assert.Equal(t, 0, mgr.ActiveCount())
	assert.Equal(t, 0, mgr.IdleCount())

	cc := mgr.GetClient(li.Addr().String())

	streamCtx, streamCancel := context.WithCancel(t.Context())
	_, err = grpc_health_v1.NewHealthClient(cc).Watch(streamCtx, &grpc_health_v1.HealthCheckRequest{Service: "test"})
	require.NoError(t, err)
	assert.Equal(t, 1, mgr.ActiveCount())
	streamCancel()
	assert.Eventually(t, func() bool {
		return mgr.ActiveCount() == 0
	}, time.Second, 100*time.Millisecond, "should move the active connection to idle")

	res, err := grpc_health_v1.NewHealthClient(cc).Check(t.Context(), &grpc_health_v1.HealthCheckRequest{Service: "test"})
	require.NoError(t, err)
	assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, res.GetStatus())

	assert.Equal(t, 0, mgr.ActiveCount())
	assert.Equal(t, 1, mgr.IdleCount())
	assert.Eventually(t, func() bool {
		return mgr.IdleCount() == 0
	}, time.Second, 100*time.Millisecond, "should close idle connections")
}
