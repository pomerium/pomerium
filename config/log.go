package config

import (
	"sync"

	"github.com/pomerium/pomerium/internal/log"
)

// The LogManager configures logging based on options.
type LogManager struct {
	mu sync.Mutex
}

// NewLogManager creates a new LogManager.
func NewLogManager(src Source) *LogManager {
	mgr := &LogManager{}
	src.OnConfigChange(mgr.OnConfigChange)
	mgr.OnConfigChange(src.GetConfig())
	return mgr
}

// Close closes the log manager.
func (mgr *LogManager) Close() error {
	return nil
}

// OnConfigChange is called whenever configuration changes.
func (mgr *LogManager) OnConfigChange(cfg *Config) {
	if cfg == nil || cfg.Options == nil {
		return
	}

	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	if cfg.Options.Debug {
		log.EnableDebug()
	} else {
		log.DisableDebug()
	}

	if cfg.Options.LogLevel != "" {
		log.SetLevel(cfg.Options.LogLevel)
	}
}
