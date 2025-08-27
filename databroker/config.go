package databroker

import "github.com/pomerium/pomerium/pkg/identity/manager"

type databrokerConfig struct {
	managerOptions []manager.Option
}

// An Option customizes the databroker.
type Option func(cfg *databrokerConfig)

// WithManagerOptions sets manager options in the databroker config.
func WithManagerOptions(managerOptions ...manager.Option) Option {
	return func(cfg *databrokerConfig) {
		cfg.managerOptions = append(cfg.managerOptions, managerOptions...)
	}
}

func getConfig(options ...Option) *databrokerConfig {
	cfg := new(databrokerConfig)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}
