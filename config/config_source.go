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

// A ChangeListener is called when configuration changes.
type ChangeListener = func(*Config)

// A ChangeDispatcher manages listeners on config changes.
type ChangeDispatcher struct {
	sync.Mutex
	onConfigChangeListeners []ChangeListener
}

// Trigger triggers a change.
func (dispatcher *ChangeDispatcher) Trigger(cfg *Config) {
	dispatcher.Lock()
	defer dispatcher.Unlock()

	for _, li := range dispatcher.onConfigChangeListeners {
		li(cfg)
	}
}

// OnConfigChange adds a listener.
func (dispatcher *ChangeDispatcher) OnConfigChange(li ChangeListener) {
	dispatcher.Lock()
	defer dispatcher.Unlock()
	dispatcher.onConfigChangeListeners = append(dispatcher.onConfigChangeListeners, li)
}

// A Source gets configuration.
type Source interface {
	GetConfig() *Config
	OnConfigChange(ChangeListener)
}

// A FileOrEnvironmentSource retrieves config options from a file or the environment.
type FileOrEnvironmentSource struct {
	configFile string

	mu     sync.RWMutex
	config *Config

	ChangeDispatcher
}

// NewFileOrEnvironmentSource creates a new FileOrEnvironmentSource.
func NewFileOrEnvironmentSource(configFile string) (*FileOrEnvironmentSource, error) {
	options, err := newOptionsFromConfig(configFile)
	if err != nil {
		return nil, err
	}

	src := &FileOrEnvironmentSource{
		configFile: configFile,
		config:     &Config{Options: options},
	}
	options.viper.OnConfigChange(src.onConfigChange)
	go options.viper.WatchConfig()

	return src, nil
}

func (src *FileOrEnvironmentSource) onConfigChange(evt fsnotify.Event) {
	src.mu.Lock()
	newOptions := handleConfigUpdate(src.configFile, src.config.Options)
	cfg := &Config{Options: newOptions}
	src.config = cfg
	src.mu.Unlock()

	src.Trigger(cfg)
}

// GetConfig gets the config.
func (src *FileOrEnvironmentSource) GetConfig() *Config {
	src.mu.RLock()
	defer src.mu.RUnlock()

	return src.config
}
