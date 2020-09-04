package manager

import (
	"sync/atomic"
	"time"

	"github.com/pomerium/pomerium/internal/directory"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

var (
	defaultGroupRefreshInterval          = 15 * time.Minute
	defaultGroupRefreshTimeout           = 10 * time.Minute
	defaultSessionRefreshGracePeriod     = 1 * time.Minute
	defaultSessionRefreshCoolOffDuration = 10 * time.Second
)

type config struct {
	authenticator                 Authenticator
	directory                     directory.Provider
	dataBrokerClient              databroker.DataBrokerServiceClient
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

// WithAuthenticator sets the authenticator in the config.
func WithAuthenticator(authenticator Authenticator) Option {
	return func(cfg *config) {
		cfg.authenticator = authenticator
	}
}

// WithDirectoryProvider sets the directory provider in the config.
func WithDirectoryProvider(directoryProvider directory.Provider) Option {
	return func(cfg *config) {
		cfg.directory = directoryProvider
	}
}

// WithDataBrokerClient sets the databroker client in the config.
func WithDataBrokerClient(dataBrokerClient databroker.DataBrokerServiceClient) Option {
	return func(cfg *config) {
		cfg.dataBrokerClient = dataBrokerClient
	}
}

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

type atomicConfig struct {
	value atomic.Value
}

func newAtomicConfig(cfg *config) *atomicConfig {
	ac := new(atomicConfig)
	ac.Store(cfg)
	return ac
}

func (ac *atomicConfig) Load() *config {
	return ac.value.Load().(*config)
}

func (ac *atomicConfig) Store(cfg *config) {
	ac.value.Store(cfg)
}
