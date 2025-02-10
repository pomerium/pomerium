package filemgr

import (
	"path/filepath"

	"github.com/pomerium/pomerium/internal/fileutil"
)

type config struct {
	cacheDir string
}

// An Option updates the config.
type Option = func(*config)

// WithCacheDir returns an Option that sets the cache dir.
func WithCacheDir(cacheDir string) Option {
	return func(cfg *config) {
		cfg.cacheDir = cacheDir
	}
}

func newConfig(options ...Option) *config {
	cfg := new(config)
	WithCacheDir(filepath.Join(fileutil.CacheDir(), "envoy", "files"))(cfg)
	for _, o := range options {
		o(cfg)
	}
	return cfg
}
