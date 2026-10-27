package enterprise

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/rs/zerolog"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/fileutil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/logutil"
)

// A Manager manages an enterprise installation.
type Manager struct {
	config.ChangeDispatcher
	ctx context.Context

	mu             sync.RWMutex
	cfg            *config.Config
	options        map[string]any
	process        *os.Process
	restartBackoff *backoff.ExponentialBackOff
}

// New creates a new enterprise manager.
func New(ctx context.Context, src config.Source) *Manager {
	mgr := &Manager{ctx: ctx}
	mgr.restartBackoff = backoff.NewExponentialBackOff(backoff.WithMaxElapsedTime(0))
	src.OnConfigChange(context.Background(), func(ctx context.Context, cfg *config.Config) {
		mgr.update(ctx, cfg)
	})
	mgr.update(context.Background(), src.GetConfig())
	return mgr
}

func (mgr *Manager) Close() {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if mgr.process != nil {
		_ = mgr.process.Kill()
		mgr.process = nil
	}
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

	mgr.restartBackoff.Reset()

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

		cmd := exec.CommandContext(mgr.ctx, "pomerium-console", "serve", "--config", path.Join(dataDir, "config.yaml")) //nolint:gosec

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
		go mgr.watchStartedCommand(cmd)
	}

	mgr.options = options
	return nil
}

func (mgr *Manager) watchStartedCommand(cmd *exec.Cmd) {
	err := cmd.Wait()

	mgr.mu.Lock()
	if cmd.Process == mgr.process {
		log.Error().Err(err).Msg("enterprise: console process exited, restarting")
		mgr.process = nil
		time.AfterFunc(mgr.restartBackoff.NextBackOff(), func() {
			mgr.mu.Lock()
			if err := mgr.updateLocked(); err != nil {
				log.Error().Err(err).Msg("enterprise: error restarting console")
			}
			mgr.mu.Unlock()
		})
	}
	mgr.mu.Unlock()
}

func buildOptions(cfg *config.Config) (options map[string]any, enabled bool, err error) {
	options = make(map[string]any)
	enabled = cfg.Options.Enterprise.IsSet && cfg.Options.Enterprise.Value.URL.IsSet
	if !enabled || true { // for now, running the embedded enterprise console is disabled
		return options, false, nil
	}

	settings := cfg.Options.Enterprise.Value
	cacheDir := fileutil.EnterpriseConsoleCacheDir()
	dataDir := fileutil.EnterpriseConsoleDataDir()
	// create the directories
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, false, fmt.Errorf("error creating enterprise console cache directory: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, false, fmt.Errorf("error creating enterprise console data directory: %w", err)
	}

	if settings.Administrators.IsSet {
		options["administrators"] = settings.Administrators.Value
	}
	if settings.AnalyticsCollectInterval.IsSet {
		options["analytics_collect_interval"] = settings.AnalyticsCollectInterval.Value.String()
	}
	if settings.AnalyticsURL.IsSet {
		options["analytics_url"] = settings.AnalyticsURL.Value
	}
	if settings.Audience.IsSet {
		options["audience"] = settings.Audience.Value
	}
	if settings.AuthenticateServiceURL.IsSet {
		options["authenticate_service_url"] = settings.AuthenticateServiceURL.Value
	}
	if settings.BindAddress.IsSet {
		options["bind_addr"] = settings.BindAddress.Value
	}
	if settings.BootstrapServiceAccount.IsSet {
		options["bootstrap_service_account"] = settings.BootstrapServiceAccount.Value
	}
	if settings.CacheDir.IsSet {
		options["cache_dir"] = settings.CacheDir.Value
	} else {
		options["cache_dir"] = cacheDir
	}
	if settings.ChangesetRequiredApprovalCount.IsSet {
		options["changeset_required_approval_count"] = int(settings.ChangesetRequiredApprovalCount.Value)
	}
	if settings.CustomerID.IsSet {
		options["customer_id"] = settings.CustomerID.Value
	}
	if settings.DangerouslyDisableAllNamespaceChecks.IsSet {
		options["dangerously_disable_all_namespace_checks"] = settings.DangerouslyDisableAllNamespaceChecks.Value
	}
	if settings.DatabaseEncryptionKey.IsSet {
		options["database_encryption_key"] = base64.StdEncoding.EncodeToString(settings.DatabaseEncryptionKey.Value)
	}
	if settings.DatabaseEncryptionKeyFile.IsSet {
		options["database_encryption_key_file"] = settings.DatabaseEncryptionKeyFile.Value
	}
	if settings.DatabaseEncryptionKeyRawFile.IsSet {
		options["database_encryption_key_raw_file"] = settings.DatabaseEncryptionKeyRawFile.Value
	}
	if !settings.DatabaseEncryptionKey.IsSet && !settings.DatabaseEncryptionKeyFile.IsSet && !settings.DatabaseEncryptionKeyRawFile.IsSet {
		// if no database encryption key was passed, used a saved database encryption key,
		// derived from the shared secret
		p := filepath.Join(dataDir, "database-encryption-key")
		databaseEncryptionKey, err := os.ReadFile(p)
		if os.IsNotExist(err) {
			// no file exists, so we need to derive the database encryption key
			sharedKey, err := cfg.Options.GetSharedKey()
			if err != nil {
				return nil, false, fmt.Errorf("error getting shared key: %w", err)
			}
			databaseEncryptionKey = cryptutil.DeriveKey(sharedKey, "database-encryption-key")
			if err := os.WriteFile(p, databaseEncryptionKey, 0o600); err != nil {
				return nil, false, fmt.Errorf("error saving database encryption key: %w", err)
			}
		} else if err != nil {
			// some other error while reading the database encryption key
			return nil, false, fmt.Errorf("error reading database encryption key: %w", err)
		}
		options["database_encryption_key"] = base64.StdEncoding.EncodeToString(databaseEncryptionKey)
	}
	if settings.DatabaseURL.IsSet {
		options["database_url"] = settings.DatabaseURL.Value
	} else {
		options["database_url"] = "sqlite://" + path.Join(dataDir, "data.sqlite")
	}
	if settings.DatabrokerServiceURLs.IsSet {
		options["databroker_service_urls"] = settings.DatabrokerServiceURLs.Value
	} else {
		urls, err := cfg.Options.GetInternalDataBrokerURLs()
		if err != nil {
			return nil, false, fmt.Errorf("error getting internal databroker service urls: %w", err)
		} else if len(urls) == 0 {
			return nil, false, fmt.Errorf("no internal databroker service urls defined")
		}
		// the enterprise console seems to prefer localhost to 127.0.0.1 for this
		rawURL := strings.ReplaceAll(urls[0].String(), "127.0.0.1:", "localhost:")
		options["databroker_service_url"] = rawURL
	}
	if settings.DebugAddress.IsSet {
		options["debug_addr"] = settings.DebugAddress.Value
	}
	if settings.DebugConfigDump.IsSet {
		options["debug_config_dump"] = settings.DebugConfigDump.Value
	}
	if settings.DirectoryProvider.IsSet {
		options["directory_provider"] = settings.DirectoryProvider.Value
	}
	if settings.DirectoryProviderOptions.IsSet {
		options["directory_provider_options"] = settings.DirectoryProviderOptions.Value
	}
	if settings.DirectoryProviderRefreshInterval.IsSet {
		options["directory_provider_refresh_interval"] = settings.DirectoryProviderRefreshInterval.Value.String()
	}
	if settings.DirectoryProviderRefreshTimeout.IsSet {
		options["directory_provider_refresh_timeout"] = settings.DirectoryProviderRefreshTimeout.Value.String()
	}
	if settings.DisableFeedbackWidget.IsSet {
		options["disable_feedback_widget"] = settings.DisableFeedbackWidget.Value
	}
	if settings.DisableRemoteDiagnostics.IsSet {
		options["disable_remote_diagnostics"] = settings.DisableRemoteDiagnostics.Value
	}
	if settings.EnableSessionRecordingQuerierCache.IsSet {
		options["enable_session_recording_querier_cache"] = settings.EnableSessionRecordingQuerierCache.Value
	}
	if settings.GRPCAddress.IsSet {
		options["grpc_addr"] = settings.GRPCAddress.Value
	}
	if settings.LicenseKey.IsSet {
		options["license_key"] = settings.LicenseKey.Value
	}
	if settings.LicenseKeyValidateOffline.IsSet {
		options["license_key_validate_offline"] = settings.LicenseKeyValidateOffline.Value
	}
	if settings.LogLevel.IsSet {
		options["log_level"] = settings.LogLevel.Value
	}
	if settings.MetricsAddress.IsSet {
		options["metrics_addr"] = settings.MetricsAddress.Value
	}
	if settings.OverrideCertificateName.IsSet {
		options["override_certificate_name"] = settings.OverrideCertificateName.Value
	}
	if settings.PrometheusDataDir.IsSet {
		options["prometheus_data_dir"] = settings.PrometheusDataDir.Value
	} else if !settings.PrometheusURL.IsSet {
		options["prometheus_data_dir"] = path.Join(dataDir, "prometheus")
	}
	if settings.PrometheusListenAddress.IsSet {
		options["prometheus_listen_addr"] = settings.PrometheusListenAddress.Value
	}
	if settings.PrometheusScrapeInterval.IsSet {
		options["prometheus_scrape_interval"] = settings.PrometheusScrapeInterval.Value.String()
	}
	if settings.PrometheusURL.IsSet {
		options["prometheus_url"] = settings.PrometheusURL.Value
	}
	if settings.PublicAddress.IsSet {
		options["public_addr"] = settings.PublicAddress.Value
	}
	if settings.SessionRecordingOptions.IsSet {
		options["session_recording_options"] = settings.SessionRecordingOptions.Value
	}
	if settings.SharedSecret.IsSet {
		options["shared_secret"] = base64.StdEncoding.EncodeToString(settings.SharedSecret.Value)
	}
	if settings.SharedSecretFile.IsSet {
		options["shared_secret_file"] = settings.SharedSecretFile.Value
	}
	if settings.SharedSecretRawFile.IsSet {
		options["shared_secret_raw_file"] = settings.SharedSecretRawFile.Value
	}
	if !settings.SharedSecret.IsSet && !settings.SharedSecretFile.IsSet && !settings.SharedSecretRawFile.IsSet {
		sharedKey, err := cfg.Options.GetSharedKey()
		if err != nil {
			return nil, false, fmt.Errorf("error getting shared key: %w", err)
		}
		options["shared_secret"] = base64.StdEncoding.EncodeToString(sharedKey)
	}
	if settings.SigningKey.IsSet {
		options["signing_key"] = base64.StdEncoding.EncodeToString(settings.SigningKey.Value)
	}
	if settings.SigningKeyFile.IsSet {
		options["signing_key_file"] = settings.SigningKeyFile.Value
	}
	if settings.SigningKeyRawFile.IsSet {
		options["signing_key_raw_file"] = settings.SigningKeyRawFile.Value
	}
	if !settings.SigningKey.IsSet && !settings.SigningKeyFile.IsSet && !settings.SigningKeyRawFile.IsSet {
		signingKey, err := cfg.Options.GetSigningKey()
		if err != nil {
			return nil, false, fmt.Errorf("error getting signing key: %w", err)
		}
		options["signing_key"] = base64.StdEncoding.EncodeToString(signingKey)
	}
	if settings.TLSDerive.IsSet {
		options["tls_derive"] = settings.TLSDerive.Value
	}
	if settings.TLSCertificate.IsSet {
		options["tls_cert"] = base64.StdEncoding.EncodeToString(settings.TLSCertificate.Value)
	}
	if settings.TLSCertificateAuthority.IsSet {
		options["tls_ca"] = base64.StdEncoding.EncodeToString(settings.TLSCertificateAuthority.Value)
	}
	if settings.TLSCertificateAuthorityFile.IsSet {
		options["tls_ca_file"] = settings.TLSCertificateAuthorityFile.Value
	}
	if settings.TLSCertificateFile.IsSet {
		options["tls_cert_file"] = settings.TLSCertificateFile.Value
	}
	if settings.TLSInsecureSkipVerify.IsSet {
		options["tls_insecure_skip_verify"] = settings.TLSInsecureSkipVerify.Value
	}
	if settings.TLSKey.IsSet {
		options["tls_key"] = base64.StdEncoding.EncodeToString(settings.TLSKey.Value)
	}
	if settings.TLSKeyFile.IsSet {
		options["tls_key_file"] = settings.TLSKeyFile.Value
	}
	if settings.URL.IsSet {
		options["url"] = settings.URL.Value
	}
	if settings.UseStaticAssets.IsSet {
		options["use_static_assets"] = settings.UseStaticAssets.Value
	}
	if settings.ValidationMode.IsSet && settings.ValidationMode.Value != configpb.EnterpriseValidationMode_ENTERPRISE_VALIDATION_MODE_UNKNOWN {
		options["validation_mode"] = strings.ToLower(strings.TrimPrefix(settings.ValidationMode.Value.String(), "ENTERPRISE_VALIDATION_MODE_"))
	} else {
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
