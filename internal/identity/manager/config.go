package manager

import "time"

var (
	defaultGroupRefreshInterval          = 10 * time.Minute
	defaultGroupRefreshTimeout           = 1 * time.Minute
	defaultSessionRefreshGracePeriod     = 1 * time.Minute
	defaultSessionRefreshCoolOffDuration = 10 * time.Second
)

type config struct {
	groupRefreshInterval          time.Duration
	groupRefreshTimeout           time.Duration
	sessionRefreshGracePeriod     time.Duration
	sessionRefreshCoolOffDuration time.Duration
}

func newConfig(options ...Option) *config {
	cfg := new(config)
	WithGroupRefreshInterval(defaultGroupRefreshInterval)(cfg)
	WithGroupRefreshTimeout(defaultGroupRefreshTimeout)(cfg)
	WithSessionRefreshGracePeriod(defaultSessionRefreshGracePeriod)(cfg)
	WithSessionRefreshCoolOffDuration(defaultSessionRefreshCoolOffDuration)(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}

// An Option customizes the configuration used for the identity manager.
type Option func(*config)

// WithGroupRefreshInterval sets the group refresh interval used by the manager.
func WithGroupRefreshInterval(interval time.Duration) Option {
	return func(cfg *config) {
		cfg.groupRefreshInterval = interval
	}
}

// WithGroupRefreshTimeout sets the group refresh timeout used by the manager.
func WithGroupRefreshTimeout(timeout time.Duration) Option {
	return func(cfg *config) {
		cfg.groupRefreshTimeout = timeout
	}
}

// WithSessionRefreshGracePeriod sets the session refresh grace period used by the manager.
func WithSessionRefreshGracePeriod(dur time.Duration) Option {
	return func(cfg *config) {
		cfg.sessionRefreshGracePeriod = dur
	}
}

// WithSessionRefreshCoolOffDuration sets the session refresh cool-off duration used by the manager.
func WithSessionRefreshCoolOffDuration(dur time.Duration) Option {
	return func(cfg *config) {
		cfg.sessionRefreshCoolOffDuration = dur
	}
}
