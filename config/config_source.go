package config

import (
	"reflect"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/mitchellh/copystructure"
	"github.com/spf13/viper"
)

// Config holds pomerium configuration options.
type Config struct {
	Options *Options
}

// Clone creates a deep clone of the config.
func (cfg *Config) Clone() *Config {
	return copystructure.Must(copystructure.Config{
		Copiers: map[reflect.Type]copystructure.CopierFunc{
			reflect.TypeOf((*viper.Viper)(nil)): func(i interface{}) (interface{}, error) {
				return i, nil
			},
		},
	}.Copy(cfg)).(*Config)
}

// A ConfigChangeListener is called when configuration changes.
type ConfigChangeListener = func(*Config)

// A ConfigChangeDispatcher manages listeners on config changes.
type ConfigChangeDispatcher struct {
	sync.Mutex
	onConfigChangeListeners []ConfigChangeListener
}

// Trigger triggers a change.
func (dispatcher *ConfigChangeDispatcher) Trigger(cfg *Config) {
	dispatcher.Lock()
	defer dispatcher.Unlock()

	for _, li := range dispatcher.onConfigChangeListeners {
		li(cfg)
	}
}

// OnConfigChange adds a listener.
func (dispatcher *ConfigChangeDispatcher) OnConfigChange(li ConfigChangeListener) {
	dispatcher.Lock()
	defer dispatcher.Unlock()
	dispatcher.onConfigChangeListeners = append(dispatcher.onConfigChangeListeners, li)
}

// A ConfigSource gets configuration.
type ConfigSource interface {
	GetConfig() *Config
	OnConfigChange(ConfigChangeListener)
}

// A FileOrEnvironmentConfigSource retrieves config options from a file or the environment.
type FileOrEnvironmentConfigSource struct {
	configFile string

	mu     sync.RWMutex
	config *Config

	ConfigChangeDispatcher
}

// NewFileOrEnvironmentConfigSource creates a new FileOrEnvironmentConfigSource.
func NewFileOrEnvironmentConfigSource(configFile string) (*FileOrEnvironmentConfigSource, error) {
	options, err := newOptionsFromConfig(configFile)
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
	newOptions := handleConfigUpdate(src.configFile, src.config.Options)
	cfg := &Config{Options: newOptions}
	src.config = cfg
	src.mu.Unlock()

	src.Trigger(cfg)
}

// GetConfig gets the config.
func (src *FileOrEnvironmentConfigSource) GetConfig() *Config {
	src.mu.RLock()
	defer src.mu.RUnlock()

	return src.config
}
