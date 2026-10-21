package config

import (
	"sync"

	"github.com/posthog/posthog-go"

	"github.com/pomerium/pomerium/internal/analytics"
)

var posthogAnalyticsProvider = sync.OnceValue(func() analytics.Provider {
	return analytics.NewPostHogProvider(posthog.New(analytics.PostHogProductionProjectID))
})

func (cfg *Config) AnalyticsProvider() analytics.Provider {
	if cfg.Options.IsRuntimeFlagSet(RuntimeFlagProductAnalytics) {
		return posthogAnalyticsProvider()
	}
	return analytics.NewNoOpProvider()
}
