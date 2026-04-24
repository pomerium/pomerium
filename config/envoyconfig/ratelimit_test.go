package envoyconfig

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
)

func TestBuildRateLimitActions(t *testing.T) {
	t.Run("nil policy", func(t *testing.T) {
		assert.Nil(t, BuildRateLimitActions(&config.Policy{}))
	})

	t.Run("with rate limit", func(t *testing.T) {
		rl := &config.RateLimitConfig{
			RequestsPerInterval: 10,
			Interval:            "60s",
		}
		p := &config.Policy{
			ID:        "route1",
			RateLimit: rl,
		}

		actions := BuildRateLimitActions(p)
		assert.Len(t, actions, 1)
		assert.Len(t, actions[0].Actions, 1)
		genericKey := actions[0].Actions[0].GetGenericKey()
		assert.NotNil(t, genericKey)
		assert.Equal(t, "destination_service", genericKey.DescriptorKey)
		assert.Equal(t, "route1", genericKey.DescriptorValue)
	})

	t.Run("with custom descriptor", func(t *testing.T) {
		rl := &config.RateLimitConfig{
			RequestsPerInterval: 5,
			Interval:            "1m",
			DescriptorKey:       "path",
			DescriptorValue:      "%PATH%",
		}
		p := &config.Policy{
			ID:        "route2",
			RateLimit: rl,
		}

		actions := BuildRateLimitActions(p)
		assert.Len(t, actions, 1)
		genericKey := actions[0].Actions[0].GetGenericKey()
		assert.Equal(t, "path", genericKey.DescriptorKey)
		assert.Equal(t, "%PATH%", genericKey.DescriptorValue)
	})
}

func TestHasRouteRateLimiting(t *testing.T) {
	t.Run("empty policies", func(t *testing.T) {
		cfg := &config.Config{
			Options: &config.Options{},
		}
		assert.False(t, HasRouteRateLimiting(cfg))
	})

	t.Run("one route with rate limit", func(t *testing.T) {
		cfg := &config.Config{
			Options: &config.Options{
				Routes: []config.Policy{
					{
						RateLimit: &config.RateLimitConfig{
							RequestsPerInterval: 1,
						},
					},
				},
			},
		}
		assert.True(t, HasRouteRateLimiting(cfg))
	})
}
