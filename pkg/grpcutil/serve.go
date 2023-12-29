package grpcutil

import (
	"context"
	"net"
	"time"

	"google.golang.org/grpc"
)

// ServeWithGracefulStop serves the gRPC listener until ctx.Done(), and then gracefully stops and waits for gracefulTimeout
// before definitively stopping.
func ServeWithGracefulStop(ctx context.Context, srv *grpc.Server, li net.Listener, gracefulTimeout time.Duration) error {
	go func() {
		// wait for the context to complete
		<-ctx.Done()

		sctx, stopped := context.WithCancel(context.Background())
		go func() {
			srv.GracefulStop()
			stopped()
		}()

		wait := time.NewTimer(gracefulTimeout)
		defer wait.Stop()

		select {
		case <-wait.C:
		case <-sctx.Done():
			return
		}

		// finally stop it completely
		srv.Stop()
	}()

	return srv.Serve(li)
}
