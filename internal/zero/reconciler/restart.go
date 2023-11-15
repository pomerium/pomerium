package reconciler

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// RunWithRestart executes execFn.
// The execution would be restarted, by means of canceling the context provided to execFn, each time restartFn returns.
// the error returned by restartFn is purely informational and does not affect the execution; may be nil.
// the loop is stopped when the context provided to RunWithRestart is canceled or execFn returns an error unrelated to its context cancellation.
func RunWithRestart(
	ctx context.Context,
	execFn func(context.Context) error,
	restartFn func(context.Context) error,
) error {
	contexts := make(chan context.Context)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	var err error
	go func() {
		err = restartWithContext(contexts, execFn)
		cancel()
		wg.Done()
	}()
	go func() {
		restartContexts(ctx, contexts, restartFn)
		wg.Done()
	}()

	wg.Wait()
	return err
}

func restartContexts(
	base context.Context,
	contexts chan<- context.Context,
	restartFn func(context.Context) error,
) {
	defer close(contexts)
	for base.Err() == nil {
		ctx, cancel := context.WithCancelCause(base)
		select {
		case contexts <- ctx:
			err := restartFn(ctx)
			cancel(fmt.Errorf("requesting restart: %w", err))
		case <-base.Done():
			cancel(fmt.Errorf("parent context canceled: %w", base.Err()))
			return
		}
	}
}

func restartWithContext(
	contexts <-chan context.Context,
	execFn func(context.Context) error,
) error {
	var err error
	for ctx := range contexts {
		err = execFn(ctx)
		if ctx.Err() == nil || !errors.Is(err, ctx.Err()) {
			return err
		}
	}
	return err
}
