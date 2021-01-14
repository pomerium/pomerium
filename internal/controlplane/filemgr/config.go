package filemgr

import (
	"os"
	"path/filepath"

	"github.com/google/uuid"
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
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = filepath.Join(os.TempDir(), uuid.New().String())
	}
	WithCacheDir(filepath.Join(cacheDir, "pomerium", "envoy", "files"))(cfg)
	for _, o := range options {
		o(cfg)
	}
	return cfg
}
