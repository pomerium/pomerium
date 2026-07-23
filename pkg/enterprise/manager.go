package enterprise

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/fileutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/logutil"
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
	src.OnConfigChange(context.Background(), func(ctx context.Context, cfg *config.Config) {
		mgr.update(ctx, cfg)
	})
	mgr.update(context.Background(), src.GetConfig())
	return mgr
}

// GetConfig returns the current config.
func (mgr *Manager) GetConfig() *config.Config {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	return mgr.cfg
}

func (mgr *Manager) update(ctx context.Context, cfg *config.Config) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	mgr.cfg = cfg.Clone()
	if err := mgr.updateLocked(); err != nil {
		log.Error().Err(err).Msg("enterprise: error updating console")
	}

	mgr.ChangeDispatcher.Trigger(ctx, mgr.cfg)
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
		cacheDir := fileutil.EnterpriseConsoleCacheDir()
		dataDir := fileutil.EnterpriseConsoleDataDir()

		// create the directories
		if err := os.MkdirAll(cacheDir, 0o700); err != nil {
			return fmt.Errorf("error creating enterprise console cache directory: %w", err)
		}
		if err := os.MkdirAll(dataDir, 0o700); err != nil {
			return fmt.Errorf("error creating enterprise console data directory: %w", err)
		}

		// write the config file
		bs, err := json.Marshal(options)
		if err != nil {
			return fmt.Errorf("error marshaling enterprise console options: %w", err)
		}
		if err := os.WriteFile(path.Join(dataDir, "config.yaml"), bs, 0o600); err != nil {
			return fmt.Errorf("error writing enterprise console config: %w", err)
		}

		log.Info().Msg("enterprise: starting console process")

		cmd := exec.Command("pomerium-console", "serve", "--config", path.Join(dataDir, "config.yaml")) //nolint:gosec

		// handle logs
		stderr, err := cmd.StderrPipe()
		if err != nil {
			return fmt.Errorf("error opening stderr pipe: %w", err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			_ = stderr.Close()
			return fmt.Errorf("error opening stdout pipe: %w", err)
		}
		go handleLogs(stderr)
		go handleLogs(stdout)

		err = cmd.Start()
		if err != nil {
			return fmt.Errorf("error starting enterprise console process: %w", err)
		}
		mgr.process = cmd.Process
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
	if !enabled {
		return options, enabled, nil
	}

	cacheDir := fileutil.EnterpriseConsoleCacheDir()
	dataDir := fileutil.EnterpriseConsoleDataDir()

	if _, ok := options["shared_secret"]; !ok {
		sharedKey, err := cfg.Options.GetSharedKey()
		if err != nil {
			return nil, false, fmt.Errorf("error getting shared key: %w", err)
		}
		options["shared_secret"] = base64.StdEncoding.EncodeToString(sharedKey)
	}

	if _, ok := options["signing_key"]; !ok {
		signingKey, err := cfg.Options.GetSigningKey()
		if err != nil {
			return nil, false, fmt.Errorf("error getting signing key: %w", err)
		}
		options["signing_key"] = base64.StdEncoding.EncodeToString(signingKey)
	}

	if _, ok := options["cache_dir"]; !ok {
		options["cache_dir"] = cacheDir
	}

	// if no database encryption key is set, use the shared secret as the database encryption key
	if _, ok := options["database_encryption_key"]; !ok {
		options["database_encryption_key"] = options["shared_secret"]
	}

	if _, ok := options["databroker_service_url"]; !ok {
		options["databroker_service_url"] = "http://localhost:5443"
	}

	if _, ok := options["database_url"]; !ok {
		options["database_url"] = "sqlite://" + path.Join(dataDir, "data.sqlite")
	}

	if _, ok := options["prometheus_data_dir"]; !ok {
		if _, ok := options["prometheus_url"]; !ok {
			options["prometheus_data_dir"] = path.Join(dataDir, "prometheus")
		}
	}

	if _, ok := options["validation_mode"]; !ok {
		options["validation_mode"] = "static"
	}

	return options, enabled, nil
}

func handleLogs(r io.ReadCloser) {
	defer r.Close()

	for ln := range logutil.IterateLines(r) {
		msg := ln
		lvl := zerolog.InfoLevel

		m := map[string]any{}
		if json.Unmarshal([]byte(ln), &m) == nil {
			msg, _ = m["message"].(string)
			delete(m, "message")
			delete(m, "time")

			lvlStr, _ := m["level"].(string)
			delete(m, "level")
			if l, err := zerolog.ParseLevel(lvlStr); err == nil {
				lvl = l
			}
		}

		log.Logger().
			WithLevel(lvl).
			Str("service", "enterprise-console").
			Fields(m).
			Msg(msg)
	}
}
