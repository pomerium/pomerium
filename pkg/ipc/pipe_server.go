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
	for {
		go func() {
			srv.serveC <- srv.serve(ctx)
		}()
		select {
		case <-ctx.Done():
			<-srv.serveC
			return fmt.Errorf("server done : %w", ctx.Err())
		case newWorkers := <-srv.updateC:
			if err := srv.Shutdown(ctx); err != nil {
				log.Ctx(ctx).Err(err).Msg("failed to shutdown pipe server workers")
			}
			srv.workers = newWorkers
		case err := <-srv.serveC:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
				return fmt.Errorf("unexpected serve error : %w", err)
			}
			return nil
		}
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

func (srv *ProtoPipeServer[Recv, Send]) OnChange(
	ctx context.Context,
	workers []*ProtoPipeWorker[Recv, Send],
) {
	ctx = srv.logWithFields(ctx)
	select {
	case srv.updateC <- workers:
		log.Ctx(ctx).Debug().Str("server", srv.Name).Msg("reloading workers")
	default:
		// do not block
		log.Ctx(ctx).Warn().Str("server", srv.Name).Msg("failed to signal worker change")
	}
}

func (srv *ProtoPipeServer[Recv, Send]) Shutdown(_ context.Context) error {
	errs := []error{}
	for _, worker := range srv.workers {
		if err := worker.receiver.Shutdown(); err != nil {
			errs = append(errs, err)
		}
	}
	select {
	case <-time.After(srv.ShutdownTimeout):
		return fmt.Errorf("proto pipe server shutdown timed out: %w", errors.Join(errs...))
	case err := <-srv.serveC:
		if err != nil && !errors.Is(err, context.Canceled) && errors.Is(err, io.EOF) {
			return err
		}
		return nil
	}
}
