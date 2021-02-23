package config

import (
	"crypto/sha256"
	"io/ioutil"
	"sync"

	"github.com/fsnotify/fsnotify"

	"github.com/pomerium/pomerium/internal/fileutil"
)

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
	mu  sync.Mutex
	cfg *Config
	lis []ChangeListener
}

// NewStaticSource creates a new StaticSource.
func NewStaticSource(cfg *Config) *StaticSource {
	return &StaticSource{cfg: cfg}
}

// GetConfig gets the config.
func (src *StaticSource) GetConfig() *Config {
	src.mu.Lock()
	defer src.mu.Unlock()

	return src.cfg
}

// SetConfig sets the config.
func (src *StaticSource) SetConfig(cfg *Config) {
	src.mu.Lock()
	defer src.mu.Unlock()

	src.cfg = cfg
	for _, li := range src.lis {
		li(cfg)
	}
}

// OnConfigChange is ignored for the StaticSource.
func (src *StaticSource) OnConfigChange(li ChangeListener) {
	src.mu.Lock()
	defer src.mu.Unlock()

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

	mu             sync.RWMutex
	computedConfig *Config

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
			src.check(underlying.GetConfig())
		}
	}()
	underlying.OnConfigChange(func(cfg *Config) {
		src.check(cfg)
	})
	src.check(underlying.GetConfig())

	return src
}

// GetConfig gets the underlying config.
func (src *FileWatcherSource) GetConfig() *Config {
	src.mu.RLock()
	defer src.mu.RUnlock()
	return src.computedConfig
}

func (src *FileWatcherSource) check(cfg *Config) {
	if cfg == nil || cfg.Options == nil {
		return
	}

	src.mu.Lock()
	defer src.mu.Unlock()

	src.watcher.Clear()

	h := sha256.New()
	fs := []string{
		cfg.Options.CAFile,
		cfg.Options.CertFile,
		cfg.Options.ClientCAFile,
		cfg.Options.DataBrokerStorageCAFile,
		cfg.Options.DataBrokerStorageCertFile,
		cfg.Options.DataBrokerStorageCertKeyFile,
		cfg.Options.KeyFile,
		cfg.Options.PolicyFile,
		cfg.Options.MetricsClientCAFile,
		cfg.Options.MetricsCertificateFile,
		cfg.Options.MetricsCertificateKeyFile,
	}

	for _, pair := range cfg.Options.CertificateFiles {
		fs = append(fs, pair.CertFile, pair.KeyFile)
	}

	for _, f := range fs {
		_, _ = h.Write([]byte{0})
		bs, err := ioutil.ReadFile(f)
		if err == nil {
			src.watcher.Add(f)
			_, _ = h.Write(bs)
		}
	}

	// update the computed config
	src.computedConfig = cfg.Clone()
	src.computedConfig.Options.Certificates = nil
	_ = src.computedConfig.Options.Validate()

	// trigger a change
	src.Trigger(src.computedConfig)
}
