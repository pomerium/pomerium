// Package filemgr defines a Manager for managing files for the controlplane.
package filemgr

import (
	"os"
	"path/filepath"
	"sync"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	"github.com/pomerium/pomerium/internal/fileutil"
	"github.com/pomerium/pomerium/internal/log"
)

// A Manager manages files for envoy.
type Manager struct {
	cfg *config

	initOnce sync.Once
	initErr  error
}

// NewManager creates a new Manager.
func NewManager(options ...Option) *Manager {
	cfg := newConfig(options...)
	return &Manager{
		cfg: cfg,
	}
}

func (mgr *Manager) init() {
	mgr.initOnce.Do(func() {
		mgr.initErr = os.MkdirAll(mgr.cfg.cacheDir, 0o700)
	})
}

// BytesDataSource returns an envoy config data source based on bytes.
func (mgr *Manager) BytesDataSource(fileName string, data []byte) *envoy_config_core_v3.DataSource {
	mgr.init()
	if mgr.initErr != nil {
		log.Error().Err(mgr.initErr).Msg("filemgr: error creating cache directory, falling back to inline bytes")
		return inlineBytes(data)
	}

	fileName = GetFileNameWithBytesHash(fileName, data)
	filePath := filepath.Join(mgr.cfg.cacheDir, fileName)

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		err = fileutil.WriteFileAtomically(filePath, data, 0o600)
		if err != nil {
			log.Error().Err(err).Msg("filemgr: error writing cache file, falling back to inline bytes")
			return inlineBytes(data)
		}
	} else if err != nil {
		log.Error().Err(err).Msg("filemgr: error reading cache file, falling back to inline bytes")
		return inlineBytes(data)
	}

	return inlineFilename(filePath)
}

// ClearCache clears the file cache.
func (mgr *Manager) ClearCache() {
	if _, err := os.Stat(mgr.cfg.cacheDir); os.IsNotExist(err) {
		return
	}

	err := filepath.Walk(mgr.cfg.cacheDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return os.Remove(p)
		}
		return nil
	})
	if err != nil {
		log.Error().Err(err).Msg("failed to clear envoy file cache")
	}
}

// FileDataSource returns an envoy config data source based on a file.
func (mgr *Manager) FileDataSource(filePath string) *envoy_config_core_v3.DataSource {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return inlineFilename(filePath)
	}
	return mgr.BytesDataSource(filepath.Base(filePath), data)
}

func inlineBytes(data []byte) *envoy_config_core_v3.DataSource {
	return &envoy_config_core_v3.DataSource{
		Specifier: &envoy_config_core_v3.DataSource_InlineBytes{
			InlineBytes: data,
		},
	}
}

func inlineFilename(name string) *envoy_config_core_v3.DataSource {
	return &envoy_config_core_v3.DataSource{
		Specifier: &envoy_config_core_v3.DataSource_Filename{
			Filename: name,
		},
	}
}
