package retry

import (
	"context"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/pomerium/pomerium/internal/log"
)

type serviceName struct{}

// WithBackoff retries the given function with an exponential backoff,
// stopping when the context is done or the function returns a terminal error.
func WithBackoff(ctx context.Context, name string, fn func(context.Context) error) error {
	name, ctx = getServiceNameContext(ctx, name)

	log.Ctx(ctx).Debug().Str("service-name", name).Msg("starting")
	defer log.Ctx(ctx).Debug().Str("service-name", name).Msg("stopped")

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 0
	return backoff.RetryNotify(
		func() error {
			err := fn(ctx)
			if IsTerminalError(err) {
				return backoff.Permanent(err)
			}
			return err
		},
		backoff.WithContext(b, ctx),
		func(err error, next time.Duration) {
			log.Ctx(ctx).Error().Err(err).Str("service-name", name).Dur("next", next).Msg("retrying")
		},
	)
}

func getServiceNameContext(ctx context.Context, name string) (string, context.Context) {
	names, ok := ctx.Value(serviceName{}).([]string)
	if ok {
		names = append(names, name)
	} else {
		names = []string{name}
	}
	return strings.Join(names, "."), context.WithValue(ctx, serviceName{}, names)
}
