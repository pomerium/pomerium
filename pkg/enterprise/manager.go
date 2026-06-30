package enterprise

import (
	"context"
	"encoding/base64"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"sync"

	"github.com/google/go-cmp/cmp"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
)

// A Manager manages an enterprise installation.
type Manager struct {
	config.ChangeDispatcher

	mu      sync.RWMutex
	cfg     *config.Config
	options map[string]any
	process *os.Process
}

// New creates a new enterprise manager.
func New(src config.Source) *Manager {
	mgr := new(Manager)
	src.OnConfigChange(context.Background(), func(_ context.Context, cfg *config.Config) {
		mgr.update(cfg)
	})
	mgr.update(src.GetConfig())
	return mgr
}

// GetConfig returns the current config.
func (mgr *Manager) GetConfig() *config.Config {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	return mgr.cfg
}

func (mgr *Manager) update(cfg *config.Config) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	mgr.cfg = cfg.Clone()
	if err := mgr.updateLocked(); err != nil {
		log.Error().Err(err).Msg("enterprise: error updating console")
	}
}

func (mgr *Manager) updateLocked() error {
	options, enabled, err := buildOptions(mgr.cfg)
	if err != nil {
		return fmt.Errorf("error building enterprise options: %w", err)
	}

	// stop the current process
	if mgr.process != nil && (!enabled || !cmp.Equal(mgr.options, options)) {
		log.Info().Msg("enterprise: stopping console process")
		err := mgr.process.Kill()
		mgr.process = nil
		if err != nil {
			return fmt.Errorf("error killing enterprise console process: %w", err)
		}
	}

	// start a new one
	if mgr.process == nil && enabled {
		log.Info().Msg("enterprise: starting console process")
		cmd := exec.Command("pomerium-console")

		err := cmd.Start()
		if err != nil {
			return fmt.Errorf("error starting enterprise console process: %w", err)
		}
	}

	mgr.options = options
	return nil
}

func buildOptions(cfg *config.Config) (options map[string]any, enabled bool, err error) {
	options = maps.Clone(cfg.Options.Enterprise)
	if options == nil {
		options = make(map[string]any)
	}

	_, enabled = options["url"]

	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		return nil, false, fmt.Errorf("error getting shared key: %w", err)
	}
	options["shared_key"] = base64.StdEncoding.EncodeToString(sharedKey)

	return options, enabled, nil
}
