package reconciler

import (
	"context"
	"errors"
	"sync"

	"github.com/pomerium/pomerium/internal/log"
)

// RunWithRestart continuously executes the provided execFn,
// restarting it when the provided restartOnErrFn returns any error other than context cancellation,
// until execFn returns an error or if the provided context gets canceled.
func RunWithRestart(
	ctx context.Context,
	execFn func(context.Context) error,
	restartOnErrFn func(context.Context) error,
) error {
	for {
		canceled, err := runWithCancel(ctx, execFn, restartOnErrFn)
		if ctx.Err() != nil || !canceled {
			return err
		}
		log.Ctx(ctx).Info().Err(err).Msg("restarting")
	}
}

func runWithCancel(
	ctx context.Context,
	execFn func(context.Context) error,
	cancelExec func(context.Context) error,
) (bool, error) {
	ctx, cancelCtx := context.WithCancelCause(ctx)

	var wg sync.WaitGroup
	wg.Add(2)

	var execErr error
	go func() {
		defer wg.Done()
		execErr = execFn(ctx)
		cancelCtx(execErr)
	}()

	restartRequiredErr := errors.New("restart requested")
	go func() {
		defer wg.Done()
		err := cancelExec(ctx)
		log.Ctx(ctx).Info().Err(err).Msg("restart requested")
		cancelCtx(restartRequiredErr)
	}()

	wg.Wait()
	return errors.Is(context.Cause(ctx), restartRequiredErr), execErr
}
