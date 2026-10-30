package contextutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/log"
)

var ErrShutdown = errors.New("pomerium shutdown requested")

func SetupSignals(ctx context.Context) context.Context {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, os.Interrupt)
	ctxCa, ca := context.WithCancelCause(ctx)
	go func() {
		defer ca(fmt.Errorf("signal received : %w", ErrShutdown))
		select {
		case <-sig:
			log.Logger().Trace().Msg("interrupt received")
		case <-ctxCa.Done():
		}
	}()
	return ctxCa
}

type shutdownInterceptor struct {
	grpc.ServerStream
	ctx context.Context
}

func (ss shutdownInterceptor) Context() context.Context {
	return ss.ctx
}

func ShutdownCauseStreamInterceptor(shutdownCtx context.Context) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, cancel := context.WithCancelCause(ss.Context())
		defer cancel(nil)
		stop := context.AfterFunc(shutdownCtx, func() { cancel(context.Cause(shutdownCtx)) })
		defer stop()
		return handler(srv, shutdownInterceptor{ServerStream: ss, ctx: ctx})
	}
}
