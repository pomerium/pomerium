package grpcutil

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
)

// ServeWithGracefulStop serves the gRPC listener until ctx.Done(), and then gracefully stops and waits for gracefulTimeout
// before definitively stopping.
func ServeWithGracefulStop(ctx context.Context, srv *grpc.Server, li net.Listener, gracefulTimeout time.Duration) error {
	go func() {
		// wait for the context to complete
		<-ctx.Done()
		log.Warn().Msg("serving context is done")

		sctx, stopped := context.WithCancel(context.Background())
		go func() {
			log.Warn().Msg("grpc server is going to gracefully stop")
			srv.GracefulStop()
			log.Warn().Msg("grpc server has gracefully stopped")
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

	err := srv.Serve(li)
	if errors.Is(err, grpc.ErrServerStopped) {
		log.Warn().Msg("we are in big trouble")
		err = nil
	}
	return err
}
