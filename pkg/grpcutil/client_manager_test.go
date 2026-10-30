package grpcutil_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
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

// TODO : bs
func TestClientManagerLeak(t *testing.T) {
	t.Parallel()

	t.Run("targets", func(t *testing.T) {
		t.Parallel()

		tr := new(connTracker)
		mgr := grpcutil.NewClientManager(noop.NewTracerProvider(), tr.options()...)
		for range 5 {
			cc := mgr.GetClient(startHealthServer(t))
			_, err := grpc_health_v1.NewHealthClient(cc).Check(t.Context(), &grpc_health_v1.HealthCheckRequest{Service: "test"})
			require.NoError(t, err)
		}
		assert.Equal(t, 5, tr.created())
		assert.Eventually(t, func() bool { return tr.open() == 0 }, 2*time.Second, 10*time.Millisecond,
			"connections to targets that are no longer used should be closed")
		assert.Equal(t, 0, mgr.ActiveCount())
		assert.Equal(t, 0, mgr.IdleCount())
	})

	t.Run("options", func(t *testing.T) {
		t.Parallel()

		tr := new(connTracker)
		mgr := grpcutil.NewClientManager(noop.NewTracerProvider(), tr.options()...)
		cc := mgr.GetClient(startHealthServer(t))
		for range 5 {
			_, err := grpc_health_v1.NewHealthClient(cc).Check(t.Context(), &grpc_health_v1.HealthCheckRequest{Service: "test"})
			require.NoError(t, err)
			mgr.UpdateOptions(tr.options()...)
		}
		assert.Equal(t, 5, tr.created())
		assert.Equal(t, 0, tr.open(), "connections built from old options should be closed")
	})

	t.Run("unary_interceptor", func(t *testing.T) {
		t.Parallel()

		errDenied := errors.New("denied")
		tr := &connTracker{dialOptions: []grpc.DialOption{
			grpc.WithUnaryInterceptor(func(context.Context, string, any, any, *grpc.ClientConn, grpc.UnaryInvoker, ...grpc.CallOption) error {
				return errDenied
			}),
		}}
		mgr := grpcutil.NewClientManager(noop.NewTracerProvider(), tr.options()...)
		cc := mgr.GetClient(startHealthServer(t))
		_, err := grpc_health_v1.NewHealthClient(cc).Check(t.Context(), &grpc_health_v1.HealthCheckRequest{Service: "test"})
		require.ErrorIs(t, err, errDenied)
		assert.Eventually(t, func() bool { return tr.open() == 0 }, 2*time.Second, 10*time.Millisecond,
			"a call rejected by an interceptor should not pin the connection open")
	})

	t.Run("stream_interceptor", func(t *testing.T) {
		t.Parallel()

		errDenied := errors.New("denied")
		tr := &connTracker{dialOptions: []grpc.DialOption{
			grpc.WithStreamInterceptor(func(context.Context, *grpc.StreamDesc, *grpc.ClientConn, string, grpc.Streamer, ...grpc.CallOption) (grpc.ClientStream, error) {
				return nil, errDenied
			}),
		}}
		mgr := grpcutil.NewClientManager(noop.NewTracerProvider(), tr.options()...)
		cc := mgr.GetClient(startHealthServer(t))
		_, err := grpc_health_v1.NewHealthClient(cc).Watch(t.Context(), &grpc_health_v1.HealthCheckRequest{Service: "test"})
		require.ErrorIs(t, err, errDenied)
		assert.Eventually(t, func() bool { return tr.open() == 0 }, 2*time.Second, 10*time.Millisecond,
			"a stream rejected by an interceptor should not pin the connection open")
	})
}

type connTracker struct {
	dialOptions []grpc.DialOption

	mu  sync.Mutex
	ccs []*grpc.ClientConn
}

func (tr *connTracker) options() []grpcutil.ClientManagerOption {
	return []grpcutil.ClientManagerOption{
		grpcutil.WithClientManagerIdleTimeout(50 * time.Millisecond),
		grpcutil.WithClientManagerNewClient(tr.newClient),
	}
}

func (tr *connTracker) newClient(target string, options ...grpc.DialOption) (*grpc.ClientConn, error) {
	options = append(options, grpc.WithTransportCredentials(insecure.NewCredentials()))
	cc, err := grpc.NewClient(target, append(options, tr.dialOptions...)...)
	if err != nil {
		return nil, err
	}
	tr.mu.Lock()
	tr.ccs = append(tr.ccs, cc)
	tr.mu.Unlock()
	return cc, nil
}

func (tr *connTracker) created() int {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return len(tr.ccs)
}

func (tr *connTracker) open() int {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	n := 0
	for _, cc := range tr.ccs {
		if cc.GetState() != connectivity.Shutdown {
			n++
		}
	}
	return n
}

func startHealthServer(t *testing.T) string {
	t.Helper()

	li, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := grpc.NewServer()
	hsrv := health.NewServer()
	hsrv.SetServingStatus("test", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(s, hsrv)
	go s.Serve(li)
	t.Cleanup(s.Stop)

	return li.Addr().String()
}
