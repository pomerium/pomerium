package identity

import "time"

var (
	defaultGroupRefreshInterval          = 10 * time.Minute
	defaultSessionRefreshCoolOffDuration = 10 * time.Second
)

type managerConfig struct {
	groupRefreshInterval          time.Duration
	sessionRefreshCoolOffDuration time.Duration
}

func newManagerConfig(options ...ManagerOption) *managerConfig {
	cfg := new(managerConfig)
	WithGroupRefreshInterval(defaultGroupRefreshInterval)(cfg)
	WithSessionRefreshCoolOffDuration(defaultSessionRefreshCoolOffDuration)(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// A ManagerOption customizes the configuration used for the identity manager.
type ManagerOption func(*managerConfig)

// WithGroupRefreshInterval sets the group refresh interval used by the manager.
func WithGroupRefreshInterval(interval time.Duration) ManagerOption {
	return func(cfg *managerConfig) {
		cfg.groupRefreshInterval = interval
	}
}

// WithSessionRefreshCoolOffDuration sets the session refresh cool-off duration used by the manager.
func WithSessionRefreshCoolOffDuration(gracePeriod time.Duration) ManagerOption {
	return func(cfg *managerConfig) {
		cfg.sessionRefreshCoolOffDuration = gracePeriod
	}
}
