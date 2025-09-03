package grpcutil_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/pomerium/pomerium/pkg/grpcutil"
)

func TestServeWithGracefulStop(t *testing.T) {
	t.Parallel()

	t.Run("immediate", func(t *testing.T) {
		t.Parallel()

		li, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)

		srv := grpc.NewServer()

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		now := time.Now()
		err = grpcutil.ServeWithGracefulStop(ctx, srv, li, time.Millisecond*100)
		elapsed := time.Since(now)
		assert.Nil(t, err)
		assert.Less(t, elapsed, time.Millisecond*100, "should complete immediately")
	})
	t.Run("graceful", func(t *testing.T) {
		t.Parallel()

		li, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)

		srv := grpc.NewServer()
		hsrv := health.NewServer()
		grpc_health_v1.RegisterHealthServer(srv, hsrv)
		hsrv.SetServingStatus("test", grpc_health_v1.HealthCheckResponse_SERVING)

		now := time.Now()
		ctx, cancel := context.WithCancel(t.Context())
		eg, ctx := errgroup.WithContext(ctx)
		eg.Go(func() error {
			return grpcutil.ServeWithGracefulStop(ctx, srv, li, time.Millisecond*100)
		})
		eg.Go(func() error {
			var cc *grpc.ClientConn
			for {
				var err error
				cc, err = grpc.Dial(li.Addr().String(),
					grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					continue
				}

				break
			}

			c := grpc_health_v1.NewHealthClient(cc)

			_, err := c.Check(ctx, &grpc_health_v1.HealthCheckRequest{
				Service: "test",
			})
			if err != nil {
				return err
			}

			// start streaming to hold open the server during graceful stop
			_, err = c.Watch(t.Context(), &grpc_health_v1.HealthCheckRequest{
				Service: "test",
			})
			if err != nil {
				return err
			}

			cancel()

			return nil
		})
		eg.Wait()
		elapsed := time.Since(now)
		assert.Greater(t, elapsed, time.Millisecond*100, "should complete after 100ms")
	})
}
