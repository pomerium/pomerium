// Package analytics collects active user metrics and reports them to the cloud dashboard
package analytics

import (
	"context"
	"fmt"
	"time"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

const (
	updateInterval = time.Hour * 6
)

// Collect collects metrics and reports them to the cloud
func Collect(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
) error {
	c := &collector{
		client:   client,
		counters: make(map[string]*ActiveUsersCounter),
	}

	now := time.Now()
	for key, resetFn := range map[string]IntervalResetFunc{
		"mau": ResetMonthlyUTC,
		"dau": ResetDailyUTC,
	} {
		state, err := LoadMetricState(ctx, client, key)
		if err != nil && !databroker.IsNotFound(err) {
			return err
		}
		if state == nil {
			c.counters[key] = NewActiveUsersCounter(resetFn, now)
			continue
		}

		counter, err := LoadActiveUsersCounter(state.Data, state.LastReset, resetFn)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Str("metric", key).Msg("failed to load metric state, resetting")
			counter = NewActiveUsersCounter(resetFn, now)
		}
		c.counters[key] = counter
	}

	return c.run(ctx, updateInterval)
}

type collector struct {
	client   databroker.DataBrokerServiceClient
	counters map[string]*ActiveUsersCounter
}

func (c *collector) run(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := c.update(ctx); err != nil {
				return err
			}
		}
	}
}

func (c *collector) update(ctx context.Context) error {
	users, err := CurrentUsers(ctx, c.client)
	if err != nil {
		return fmt.Errorf("failed to get current users: %w", err)
	}

	now := time.Now()
	for key, counter := range c.counters {
		updated := counter.Update(users, now)
		if !updated {
			log.Ctx(ctx).Debug().Msgf("metric %s not changed: %d", key, counter.Count())
			continue
		}
		log.Ctx(ctx).Debug().Msgf("metric %s updated: %d", key, counter.Count())

		data, err := counter.ToBinary()
		if err != nil {
			return fmt.Errorf("failed to marshal metric %s: %w", key, err)
		}

		err = SaveMetricState(ctx, c.client, key, data, counter.GetLastReset())
		if err != nil {
			return fmt.Errorf("failed to save metric %s: %w", key, err)
		}
	}

	return nil
}
