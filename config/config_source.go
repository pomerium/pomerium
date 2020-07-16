package config

import (
	"sync"

	"github.com/fsnotify/fsnotify"
)

// Config holds pomerium configuration options.
type Config struct {
	Options *Options
}

// A ConfigChangeListener is called when configuration changes.
type ConfigChangeListener = func(*Config)

// A ConfigSource gets configuration.
type ConfigSource interface {
	GetConfig() (*Config, error)
	OnConfigChange(ConfigChangeListener)
}

// A FileOrEnvironmentConfigSource retrieves config options from a file or the environment.
type FileOrEnvironmentConfigSource struct {
	configFile string

	mu                      sync.RWMutex
	config                  *Config
	onConfigChangeListeners []ConfigChangeListener
}

// NewFileOrEnvironmentConfigSource creates a new FileOrEnvironmentConfigSource.
func NewFileOrEnvironmentConfigSource(configFile string) (*FileOrEnvironmentConfigSource, error) {
	options, err := NewOptionsFromConfig(configFile)
	if err != nil {
		return nil, err
	}

	src := &FileOrEnvironmentConfigSource{
		configFile: configFile,
		config:     &Config{Options: options},
	}
	options.viper.OnConfigChange(src.onConfigChange)
	go options.viper.WatchConfig()

	return src, nil
}

func (src *FileOrEnvironmentConfigSource) onConfigChange(evt fsnotify.Event) {
	src.mu.Lock()
	newOptions := handleConfigUpdate(src.configFile, src.config.Options, nil)
	cfg := &Config{Options: newOptions}
	src.config = cfg
	src.mu.Unlock()

	for _, li := range src.onConfigChangeListeners {
		li(cfg)
	}
}

// GetConfig gets the config.
func (src *FileOrEnvironmentConfigSource) GetConfig() (*Config, error) {
	src.mu.RLock()
	defer src.mu.RUnlock()

	return src.config, nil
}

// OnConfigChange registers a listener for config changes.
func (src *FileOrEnvironmentConfigSource) OnConfigChange(li ConfigChangeListener) {
	src.mu.Lock()
	src.onConfigChangeListeners = append(src.onConfigChangeListeners, li)
	src.mu.Unlock()
}
