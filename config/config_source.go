package config

import (
	"context"
	"crypto/sha256"
	"os"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/fileutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/netutil"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
)

// A ChangeListener is called when configuration changes.
type ChangeListener = func(context.Context, *Config)

// A ChangeDispatcher manages listeners on config changes.
type ChangeDispatcher struct {
	sync.Mutex
	onConfigChangeListeners []ChangeListener
}

// Trigger triggers a change.
func (dispatcher *ChangeDispatcher) Trigger(ctx context.Context, cfg *Config) {
	dispatcher.Lock()
	defer dispatcher.Unlock()

	for _, li := range dispatcher.onConfigChangeListeners {
		li(ctx, cfg)
	}
}

// OnConfigChange adds a listener.
func (dispatcher *ChangeDispatcher) OnConfigChange(ctx context.Context, li ChangeListener) {
	dispatcher.Lock()
	defer dispatcher.Unlock()
	dispatcher.onConfigChangeListeners = append(dispatcher.onConfigChangeListeners, li)
}

// A Source gets configuration.
type Source interface {
	GetConfig() *Config
	OnConfigChange(context.Context, ChangeListener)
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
func (src *StaticSource) SetConfig(ctx context.Context, cfg *Config) {
	src.mu.Lock()
	defer src.mu.Unlock()

	src.cfg = cfg
	for _, li := range src.lis {
		li(ctx, cfg)
	}
}

// OnConfigChange is ignored for the StaticSource.
func (src *StaticSource) OnConfigChange(ctx context.Context, li ChangeListener) {
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
func NewFileOrEnvironmentSource(
	configFile, envoyVersion string,
) (*FileOrEnvironmentSource, error) {
	ctx := log.WithContext(context.TODO(), func(c zerolog.Context) zerolog.Context {
		return c.Str("config_file_source", configFile)
	})

	options, err := newOptionsFromConfig(configFile)
	if err != nil {
		return nil, err
	}

	ports, err := netutil.AllocatePorts(5)
	if err != nil {
		return nil, err
	}
	grpcPort := ports[0]
	httpPort := ports[1]
	outboundPort := ports[2]
	metricsPort := ports[3]
	debugPort := ports[4]

	cfg := &Config{
		Options:      options,
		EnvoyVersion: envoyVersion,

		GRPCPort:     grpcPort,
		HTTPPort:     httpPort,
		OutboundPort: outboundPort,
		MetricsPort:  metricsPort,
		DebugPort:    debugPort,
	}
	metrics.SetConfigInfo(ctx, cfg.Options.Services, "local", cfg.Checksum(), true)

	src := &FileOrEnvironmentSource{
		configFile: configFile,
		config:     cfg,
	}
	options.viper.OnConfigChange(src.onConfigChange(ctx))
	go options.viper.WatchConfig()

	return src, nil
}

func (src *FileOrEnvironmentSource) onConfigChange(ctx context.Context) func(fsnotify.Event) {
	return func(evt fsnotify.Event) {
		ctx := log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
			return c.Str("config_change_id", uuid.New().String())
		})
		log.Info(ctx).Msg("config: file updated, reconfiguring...")
		src.mu.Lock()
		cfg := src.config
		options, err := newOptionsFromConfig(src.configFile)
		if err == nil {
			cfg = cfg.Clone()
			cfg.Options = options
			metrics.SetConfigInfo(ctx, cfg.Options.Services, "local", cfg.Checksum(), true)
		} else {
			log.Error(ctx).Err(err).Msg("config: error updating config")
			metrics.SetConfigInfo(ctx, cfg.Options.Services, "local", cfg.Checksum(), false)
		}
		src.mu.Unlock()

		src.Trigger(ctx, cfg)
	}
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

// NewFileWatcherSource creates a new FileWatcherSource
func NewFileWatcherSource(underlying Source) *FileWatcherSource {
	src := &FileWatcherSource{
		underlying: underlying,
		watcher:    fileutil.NewWatcher(),
	}

	ch := src.watcher.Bind()
	go func() {
		for range ch {
			src.check(context.TODO(), underlying.GetConfig())
		}
	}()
	underlying.OnConfigChange(context.TODO(), func(ctx context.Context, cfg *Config) {
		src.check(ctx, cfg)
	})
	src.check(context.TODO(), underlying.GetConfig())

	return src
}

// GetConfig gets the underlying config.
func (src *FileWatcherSource) GetConfig() *Config {
	src.mu.RLock()
	defer src.mu.RUnlock()
	return src.computedConfig
}

func (src *FileWatcherSource) check(ctx context.Context, cfg *Config) {
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
		cfg.Options.ClientCRLFile,
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

	for _, policy := range cfg.Options.Policies {
		fs = append(fs,
			policy.KubernetesServiceAccountTokenFile,
			policy.TLSClientCertFile,
			policy.TLSClientKeyFile,
			policy.TLSCustomCAFile,
			policy.TLSDownstreamClientCAFile,
		)
	}

	for _, f := range fs {
		_, _ = h.Write([]byte{0})
		bs, err := os.ReadFile(f)
		if err == nil {
			src.watcher.Add(f)
			_, _ = h.Write(bs)
		}
	}

	// update the computed config
	src.computedConfig = cfg.Clone()

	// trigger a change
	src.Trigger(ctx, src.computedConfig)
}
