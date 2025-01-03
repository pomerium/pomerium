package snippets

import (
	"context"
	"errors"
	"net/http"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/testenv"
)

func RunWithDelayedShutdown(ctx context.Context, serve func() error, stop func()) func() error {
	env := testenv.EnvFromContext(ctx)

	stopping := make(chan struct{})
	serveExited := make(chan error, 1)
	env.OnStateChanged(testenv.Stopping, func() {
		close(stopping)
	})
	cancel := env.OnStateChanged(testenv.Stopped, func() {
		stop()
		if err := <-serveExited; err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Ctx(ctx).Err(err).Msg("error stopping server")
		}
	})
	go func() {
		serveExited <- serve()
		close(serveExited)
	}()

	return func() error {
		select {
		case <-stopping:
			return nil
		case err := <-serveExited:
			cancel()
			return err
		}
	}
}
