// Package analytics collects active user metrics and reports them to the cloud dashboard
package sessions

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// Collect collects metrics and stores them in the databroker
func Collect(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	updateInterval time.Duration,
) error {
	c := &collector{
		client:         client,
		counters:       make(map[string]*ActiveUsersCounter),
		updateInterval: updateInterval,
	}

	return c.run(ctx)
}

type collector struct {
	client         databroker.DataBrokerServiceClient
	counters       map[string]*ActiveUsersCounter
	updateInterval time.Duration
}

func (c *collector) run(ctx context.Context) error {
	err := c.loadCounters(ctx)
	if err != nil {
		return fmt.Errorf("failed to load counters: %w", err)
	}

	err = c.runPeriodicUpdate(ctx)
	if err != nil {
		return fmt.Errorf("failed to run periodic update: %w", err)
	}

	return nil
}

func (c *collector) loadCounters(ctx context.Context) error {
	now := time.Now()
	for key, resetFn := range map[string]IntervalResetFunc{
		"mau": ResetMonthlyUTC,
		"dau": ResetDailyUTC,
	} {
		state, err := LoadMetricState(ctx, c.client, key)
		if err != nil && !errors.Is(err, databroker.ErrRecordNotFound) {
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

	return nil
}

func (c *collector) runPeriodicUpdate(ctx context.Context) error {
	ticker := time.NewTicker(c.updateInterval)
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
		before := counter.Count()
		after, _ := counter.Update(users, now)
		if before == after {
			log.Ctx(ctx).Debug().Msgf("metric %s not changed: %d", key, counter.Count())
			continue
		}
		log.Ctx(ctx).Debug().Msgf("metric %s updated: %d", key, counter.Count())

		data, err := counter.ToBinary()
		if err != nil {
			return fmt.Errorf("failed to marshal metric %s: %w", key, err)
		}

		err = SaveMetricState(ctx, c.client, key, data, after, counter.GetLastReset())
		if err != nil {
			return fmt.Errorf("failed to save metric %s: %w", key, err)
		}
	}

	return nil
}
