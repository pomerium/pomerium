package config

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/cespare/xxhash/v2"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/internal/fileutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/pkg/netutil"
	"github.com/pomerium/pomerium/pkg/slices"
)

// A ChangeListener is called when configuration changes.
type ChangeListener = func(context.Context, *Config)

type changeDispatcherEvent struct {
	cfg *Config
}

// A ChangeDispatcher manages listeners on config changes.
type ChangeDispatcher struct {
	target events.Target[changeDispatcherEvent]
}

// Trigger triggers a change.
func (dispatcher *ChangeDispatcher) Trigger(ctx context.Context, cfg *Config) {
	dispatcher.target.Dispatch(ctx, changeDispatcherEvent{
		cfg: cfg,
	})
}

// OnConfigChange adds a listener.
func (dispatcher *ChangeDispatcher) OnConfigChange(_ context.Context, li ChangeListener) {
	dispatcher.target.AddListener(func(ctx context.Context, evt changeDispatcherEvent) {
		li(ctx, evt.cfg)
	})
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
func (src *StaticSource) OnConfigChange(_ context.Context, li ChangeListener) {
	src.mu.Lock()
	defer src.mu.Unlock()

	src.lis = append(src.lis, li)
}

// A FileOrEnvironmentSource retrieves config options from a file or the environment.
type FileOrEnvironmentSource struct {
	configFile string
	watcher    *fileutil.Watcher

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

	cfg := &Config{
		Options:      options,
		EnvoyVersion: envoyVersion,
	}

	ports, err := netutil.AllocatePorts(6)
	if err != nil {
		return nil, fmt.Errorf("allocating ports: %w", err)
	}

	cfg.AllocatePorts(*(*[6]string)(ports))

	metrics.SetConfigInfo(ctx, cfg.Options.Services, "local", cfg.Checksum(), true)

	src := &FileOrEnvironmentSource{
		configFile: configFile,
		watcher:    fileutil.NewWatcher(),
		config:     cfg,
	}
	if configFile != "" {
		if cfg.Options.IsRuntimeFlagSet(RuntimeFlagConfigHotReload) {
			src.watcher.Watch(ctx, []string{configFile})
		} else {
			log.Info(ctx).Msg("hot reload disabled")
			src.watcher.Watch(ctx, nil)
		}
	}
	ch := src.watcher.Bind()
	go func() {
		for range ch {
			src.check(ctx)
		}
	}()

	return src, nil
}

func (src *FileOrEnvironmentSource) check(ctx context.Context) {
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
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
		log.Ctx(ctx).Error().Err(err).Msg("config: error updating config")
		metrics.SetConfigInfo(ctx, cfg.Options.Services, "local", cfg.Checksum(), false)
	}
	src.config = cfg
	src.mu.Unlock()

	log.Info(ctx).Msg("config: loaded configuration")

	src.Trigger(ctx, cfg)
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

	mu   sync.RWMutex
	hash uint64
	cfg  *Config

	ChangeDispatcher
}

// NewFileWatcherSource creates a new FileWatcherSource
func NewFileWatcherSource(ctx context.Context, underlying Source) *FileWatcherSource {
	cfg := underlying.GetConfig()
	src := &FileWatcherSource{
		underlying: underlying,
		watcher:    fileutil.NewWatcher(),
		cfg:        cfg,
	}

	ch := src.watcher.Bind()
	go func() {
		for range ch {
			src.onFileChange(ctx)
		}
	}()
	underlying.OnConfigChange(ctx, func(ctx context.Context, cfg *Config) {
		src.onConfigChange(ctx, cfg)
	})
	src.onConfigChange(ctx, cfg)

	return src
}

// GetConfig gets the underlying config.
func (src *FileWatcherSource) GetConfig() *Config {
	src.mu.RLock()
	defer src.mu.RUnlock()

	return src.cfg
}

func (src *FileWatcherSource) onConfigChange(ctx context.Context, cfg *Config) {
	// update the file watcher with paths from the config
	if cfg.Options.IsRuntimeFlagSet(RuntimeFlagConfigHotReload) {
		src.watcher.Watch(ctx, getAllConfigFilePaths(cfg))
	} else {
		src.watcher.Watch(ctx, nil)
	}

	src.mu.Lock()
	defer src.mu.Unlock()

	// store the config and trigger an update
	src.cfg = cfg.Clone()
	src.hash = getAllConfigFilePathsHash(src.cfg)
	log.Info(ctx).Uint64("hash", src.hash).Msg("config/filewatchersource: underlying config change, triggering update")
	src.Trigger(ctx, src.cfg)
}

func (src *FileWatcherSource) onFileChange(ctx context.Context) {
	src.mu.Lock()
	defer src.mu.Unlock()

	hash := getAllConfigFilePathsHash(src.cfg)

	if hash == src.hash {
		log.Info(ctx).Uint64("hash", src.hash).Msg("config/filewatchersource: no change detected")
	} else {
		// if the hash changed, trigger an update
		// the actual config will be identical
		src.hash = hash
		log.Info(ctx).Uint64("hash", src.hash).Msg("config/filewatchersource: change detected, triggering update")
		src.Trigger(ctx, src.cfg)
	}
}

func getAllConfigFilePathsHash(cfg *Config) uint64 {
	// read all the config files and build a hash from their contents
	h := xxhash.New()
	for _, f := range getAllConfigFilePaths(cfg) {
		_, _ = h.Write([]byte{0})
		f, err := os.Open(f)
		if err == nil {
			_, _ = io.Copy(h, f)
			_ = f.Close()
		}
	}
	return h.Sum64()
}

func getAllConfigFilePaths(cfg *Config) []string {
	fs := []string{
		cfg.Options.CAFile,
		cfg.Options.CertFile,
		cfg.Options.ClientSecretFile,
		cfg.Options.CookieSecretFile,
		cfg.Options.DataBrokerStorageConnectionStringFile,
		cfg.Options.DataBrokerStorageCAFile,
		cfg.Options.DataBrokerStorageCertFile,
		cfg.Options.DataBrokerStorageCertKeyFile,
		cfg.Options.DownstreamMTLS.CAFile,
		cfg.Options.DownstreamMTLS.CRLFile,
		cfg.Options.KeyFile,
		cfg.Options.MetricsCertificateFile,
		cfg.Options.MetricsCertificateKeyFile,
		cfg.Options.MetricsClientCAFile,
		cfg.Options.PolicyFile,
		cfg.Options.SharedSecretFile,
		cfg.Options.SigningKeyFile,
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

	fs = slices.Filter(fs, func(s string) bool {
		return s != ""
	})

	return fs
}
