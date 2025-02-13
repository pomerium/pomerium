package fileutil

import (
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
)

// CacheDir returns $XDG_CACHE_HOME/pomerium, or $HOME/.cache/pomerium, or /tmp/pomerium/cache
func CacheDir() string {
	dir, err := os.UserCacheDir()
	if err == nil {
		dir = filepath.Join(dir, "pomerium")
	} else {
		dir = filepath.Join(os.TempDir(), "pomerium", "cache")
		log.Error().Msgf("user cache directory not set, defaulting to %s", dir)
	}
	return dir
}

// DataDir returns $XDG_DATA_HOME/pomerium, or $HOME/.local/share/pomerium, or /tmp/pomerium/data
func DataDir() string {
	dir := os.Getenv("XDG_DATA_HOME")
	if dir != "" {
		dir = filepath.Join(dir, "pomerium")
	} else {
		if home, err := os.UserHomeDir(); err == nil {
			dir = filepath.Join(home, ".local", "share", "pomerium")
		} else {
			dir = filepath.Join(os.TempDir(), "pomerium", "data")
		}
		log.Error().Msgf("user data directory not set, defaulting to %s", dir)
	}
	return dir
}
