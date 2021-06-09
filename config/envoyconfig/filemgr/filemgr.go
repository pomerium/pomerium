// Package filemgr defines a Manager for managing files for the controlplane.
package filemgr

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/martinlindhe/base36"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// A Manager manages files for envoy.
type Manager struct {
	cfg *config
}

// NewManager creates a new Manager.
func NewManager(options ...Option) *Manager {
	cfg := newConfig(options...)
	return &Manager{
		cfg: cfg,
	}
}

// BytesDataSource returns an envoy config data source based on bytes.
func (mgr *Manager) BytesDataSource(fileName string, data []byte) *envoy_config_core_v3.DataSource {
	h := base36.EncodeBytes(cryptutil.Hash("filemgr", data))
	ext := filepath.Ext(fileName)
	fileName = fmt.Sprintf("%s-%x%s", fileName[:len(fileName)-len(ext)], h, ext)

	if err := os.MkdirAll(mgr.cfg.cacheDir, 0o700); err != nil {
		log.Error(context.TODO()).Err(err).Msg("filemgr: error creating cache directory, falling back to inline bytes")
		return inlineBytes(data)
	}

	filePath := filepath.Join(mgr.cfg.cacheDir, fileName)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		err = ioutil.WriteFile(filePath, data, 0o600)
		if err != nil {
			log.Error(context.TODO()).Err(err).Msg("filemgr: error writing cache file, falling back to inline bytes")
			return inlineBytes(data)
		}
	} else if err != nil {
		log.Error(context.TODO()).Err(err).Msg("filemgr: error reading cache file, falling back to inline bytes")
		return inlineBytes(data)
	}

	return inlineFilename(filePath)
}

// ClearCache clears the file cache.
func (mgr *Manager) ClearCache() {
	err := filepath.Walk(mgr.cfg.cacheDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		return os.Remove(p)
	})
	if err != nil {
		log.Error(context.TODO()).Err(err).Msg("failed to clear envoy file cache")
	}
}

// FileDataSource returns an envoy config data source based on a file.
func (mgr *Manager) FileDataSource(filePath string) *envoy_config_core_v3.DataSource {
	data, err := ioutil.ReadFile(filePath)
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
