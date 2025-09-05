package contextutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/pomerium/pomerium/internal/log"
)

var ErrShutdown = errors.New("pomerium shutdown requested")

func SetupSignals(ctx context.Context) context.Context {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
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
