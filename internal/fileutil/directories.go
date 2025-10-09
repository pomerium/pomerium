package fileutil

import (
	"os"
	"path/filepath"
	"runtime"
)

// CacheDir returns $XDG_CACHE_HOME/pomerium, or $HOME/.cache/pomerium, or /tmp/pomerium/cache
func CacheDir() string {
	dir, err := os.UserCacheDir()
	if err == nil {
		dir = filepath.Join(dir, "pomerium")
	} else {
		dir = filepath.Join(os.TempDir(), "pomerium", "cache")
	}
	return dir
}

// DataDir returns $XDG_DATA_HOME/pomerium, or $HOME/.local/share/pomerium, or /var/tmp/pomerium/data
func DataDir() string {
	if runtime.GOOS == "darwin" {
		if dir, err := os.UserHomeDir(); err == nil {
			return filepath.Join(dir, "Library", "Application Support", "pomerium")
		}
	}

	if dir := os.Getenv("XDG_DATA_HOME"); dir != "" {
		return filepath.Join(dir, "pomerium")
	}

	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "share", "pomerium")
	}

	return "/var/tmp/pomerium/data"
}
