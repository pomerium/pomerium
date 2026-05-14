package ipc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/log"
)

func (srv *ProtoPipeServer[Recv, Send]) logWithFields(ctx context.Context) context.Context {
	return log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("server", srv.Name).Str("service", serviceName)
	})
}

func (srv *ProtoPipeServer[Recv, Send]) Serve(ctx context.Context) error {
	ctx = srv.logWithFields(ctx)
	defer close(srv.doneC)

	serveC := make(chan error, 1)
	go func() {
		serveC <- srv.serve(ctx)
	}()
	select {
	case <-ctx.Done():
		<-serveC
		return fmt.Errorf("server done : %w", ctx.Err())
	case err := <-serveC:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
			return fmt.Errorf("unexpected serve error : %w", err)
		}
		return nil
	}
}

func (srv *ProtoPipeServer[Recv, Send]) serve(ctx context.Context) error {
	eg, eCtx := errgroup.WithContext(ctx)
	for i, worker := range srv.workers {
		eg.Go(func() error {
			workerCtx := log.WithContext(eCtx, func(c zerolog.Context) zerolog.Context {
				return c.Int("worker", i)
			})
			log.Ctx(workerCtx).Debug().Msg("starting worker")
			return worker.run(workerCtx, srv.handler)
		})
	}
	return eg.Wait()
}

func (srv *ProtoPipeServer[Recv, Send]) shutdown(ctx context.Context) error {
	errs := []error{}
	for i, worker := range srv.workers {
		log.Ctx(ctx).Info().Int("worker", i).
			Msg("signaled worker shutdown")
		rErr := worker.Receiver.Shutdown()
		sErr := worker.Sender.Shutdown()
		if rErr != nil {
			errs = append(errs, rErr)
		}
		if sErr != nil {
			errs = append(errs, sErr)
		}
	}
	return errors.Join(errs...)
}

func (srv *ProtoPipeServer[Recv, Send]) Shutdown(ctx context.Context) error {
	err := srv.shutdown(ctx)
	select {
	case <-srv.doneC:
		return nil
	case <-time.After(srv.ShutdownTimeout):
		return fmt.Errorf("proto pipe server shutdown timed out: %w", err)
	}
}
