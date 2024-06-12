package retry

import (
	"context"

	"github.com/cenkalti/backoff/v4"
)

// WithBackoff retries the given function with an exponential backoff,
// stopping when the context is done or the function returns a terminal error.
func WithBackoff(ctx context.Context, fn func(context.Context) error) error {
	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 0
	return backoff.Retry(
		func() error {
			err := fn(ctx)
			if IsTerminalError(err) {
				return backoff.Permanent(err)
			}
			return err
		},
		backoff.WithContext(b, ctx),
	)
}
