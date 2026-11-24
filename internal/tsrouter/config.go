package tsrouter

import (
	"path/filepath"

	"github.com/pomerium/pomerium/internal/fileutil"
)

type tsRouterConfig struct {
	directory string
}

// An Option customizes the config.
type Option func(cfg *tsRouterConfig)

// WithDirectory sets the directory to use the tsrouter.
func WithDirectory(directory string) Option {
	return func(cfg *tsRouterConfig) {
		cfg.directory = directory
	}
}

func getTSRouterConfig(options ...Option) *tsRouterConfig {
	cfg := new(tsRouterConfig)
	WithDirectory(filepath.Join(fileutil.DataDir(), "tsrouter"))(cfg)
	for _, option := range options {
		option(cfg)
	}
	return cfg
}
