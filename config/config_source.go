package config

import (
	"os"
	"sync"

	"github.com/fsnotify/fsnotify"

	"github.com/pomerium/pomerium/internal/fileutil"
)

// Config holds pomerium configuration options.
type Config struct {
	Options *Options
}

// Clone creates a clone of the config.
func (cfg *Config) Clone() *Config {
	newOptions := new(Options)
	*newOptions = *cfg.Options
	return &Config{
		Options: newOptions,
	}
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

// A StaticSource always returns the same config. Useful for testing.
type StaticSource struct {
	cfg *Config
	lis []ChangeListener
}

// NewStaticSource creates a new StaticSource.
func NewStaticSource(cfg *Config) *StaticSource {
	return &StaticSource{cfg: cfg}
}

// GetConfig gets the config.
func (src *StaticSource) GetConfig() *Config {
	return src.cfg
}

// SetConfig sets the config.
func (src *StaticSource) SetConfig(cfg *Config) {
	src.cfg = cfg
	for _, li := range src.lis {
		li(cfg)
	}
}

// OnConfigChange is ignored for the StaticSource.
func (src *StaticSource) OnConfigChange(li ChangeListener) {
	src.lis = append(src.lis, li)
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

// FileWatcherSource is a config source which triggers a change any time a file in the options changes.
type FileWatcherSource struct {
	underlying Source
	watcher    *fileutil.Watcher

	ChangeDispatcher
}

// NewFileWatcherSource creates a new FileWatcherSource.
func NewFileWatcherSource(underlying Source) *FileWatcherSource {
	src := &FileWatcherSource{
		underlying: underlying,
		watcher:    fileutil.NewWatcher(),
	}

	ch := src.watcher.Bind()
	go func() {
		for range ch {
			src.Trigger(src.GetConfig())
		}
	}()
	underlying.OnConfigChange(src.onConfigChange)

	return src
}

// GetConfig gets the underlying config.
func (src *FileWatcherSource) GetConfig() *Config {
	return src.underlying.GetConfig()
}

func (src *FileWatcherSource) onConfigChange(cfg *Config) {
	defer src.Trigger(cfg)
	src.watcher.Clear()

	fs := []string{
		cfg.Options.CAFile,
		cfg.Options.CertFile,
		cfg.Options.ClientCAFile,
		cfg.Options.DataBrokerStorageCAFile,
		cfg.Options.DataBrokerStorageCertFile,
		cfg.Options.DataBrokerStorageCertKeyFile,
		cfg.Options.KeyFile,
		cfg.Options.PolicyFile,
	}
	for _, cf := range cfg.Options.CertificateFiles {
		fs = append(fs, cf.CertFile, cf.KeyFile)
	}
	for _, f := range fs {
		if _, err := os.Stat(f); err == nil {
			src.watcher.Add(f)
		}
	}
}
