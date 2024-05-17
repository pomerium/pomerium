package healthcheck

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v4"
)

const (
	runHealthChecksMaxInterval = time.Minute * 30
	runHealthCheckMinInterval  = time.Minute
)

func (c *checker) Scheduler(ctx context.Context) {
	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 0
	bo.MaxInterval = runHealthChecksMaxInterval
	bo.InitialInterval = runHealthCheckMinInterval
	bo.Reset()

	tm := time.NewTimer(runHealthCheckMinInterval)
	defer tm.Stop()

	select {
	case <-ctx.Done():
		return
	case <-tm.C:
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.forceCheck:
		case <-tm.C:
		}

		next := runHealthChecksMaxInterval
		err := c.CheckRoutes(ctx)
		if err != nil {
			next = bo.NextBackOff()
		} else {
			bo.Reset()
		}
		if !tm.Stop() {
			select {
			case <-tm.C:
			default:
			}
		}
		tm.Reset(next)
	}
}
