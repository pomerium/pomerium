// Package httputil contains additional functionality for working with http.
package httputil

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// ServeWithGracefulStop serves the HTTP listener until ctx.Done(), and then gracefully stops and waits for gracefulTimeout
// before definitively stopping.
func ServeWithGracefulStop(ctx context.Context, handler http.Handler, li net.Listener, gracefulTimeout time.Duration) error {
	// create a context that will be used for the http requests
	// it will only be cancelled when baseCancel is called but will
	// preserve the values from ctx
	baseCtx, baseCancel := context.WithCancelCause(context.WithoutCancel(ctx))

	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv := http.Server{
		Handler: handler,
		BaseContext: func(_ net.Listener) context.Context {
			return baseCtx
		},
		Protocols: p,
	}

	go func() {
		<-ctx.Done()

		// create a context that will cancel after the graceful timeout
		timeoutCtx, clearTimeout := context.WithTimeout(context.Background(), gracefulTimeout)
		defer clearTimeout()

		// shut the http server down
		_ = srv.Shutdown(timeoutCtx)

		// cancel the base context used for http requests
		baseCancel(ctx.Err())
	}()

	err := srv.Serve(li)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	return err
}
