package enterprise

import (
	"bytes"
	"encoding/base64"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/fileutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func TestBuildOptions(t *testing.T) {
	t.Skip("the embedded enterprise console is disabled")

	dir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
	t.Setenv("HOME", filepath.Join(dir, "home"))
	t.Run("disabled", func(t *testing.T) {
		cfg := config.New(config.NewDefaultOptions())
		options, enabled, err := buildOptions(cfg)
		assert.NoError(t, err)
		assert.False(t, enabled)
		assert.Empty(t, options)
	})
	t.Run("enabled", func(t *testing.T) {
		cfg := config.New(config.NewDefaultOptions())
		cfg.Options.SharedKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xA0}, 32))
		cfg.Options.Enterprise = nullable.From(config.EnterpriseSettings{
			URL: nullable.From("https://example.com"),
		})
		options, enabled, err := buildOptions(cfg)
		assert.NoError(t, err)
		assert.True(t, enabled)
		assert.Equal(t, map[string]any{
			"cache_dir":               fileutil.EnterpriseConsoleCacheDir(),
			"database_encryption_key": "bDofqoe3k4bupJ/8cEjiof1TYB+MEZPLrqlEXiO1qF0=",
			"database_url":            "sqlite://" + path.Join(fileutil.EnterpriseConsoleDataDir(), "data.sqlite"),
			"databroker_service_url":  "http://localhost:5443",
			"prometheus_data_dir":     filepath.Join(fileutil.EnterpriseConsoleDataDir(), "prometheus"),
			"url":                     "https://example.com",
			"shared_secret":           "oKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKA=",
			"signing_key":             "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUlSMHFBTklRUlJvNTNyaFpIRGwyRG9iYXFUMnlXMk0xWlgvOHdyQ05wUFlvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFT0tSS2tkRmZjY2FRcVFqaUEvQ0t1NHZTM3IyUVVQZUtoS2ZxbkxiVFRic09PcjRGN1h3UQovYWpmWFdVcFhUUWFQdDZncW1oeGREMHp0VFVQYm10NUp3PT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo=",
			"validation_mode":         "static",
		}, options)
	})
	t.Run("options", func(t *testing.T) {
		cfg := config.New(config.NewDefaultOptions())
		cfg.Options.SharedKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xA0}, 32))
		cfg.Options.Enterprise = nullable.From(config.EnterpriseSettings{
			Administrators:                       nullable.From([]string{"u1", "u2", "u3"}),
			AnalyticsCollectInterval:             nullable.From(3 * time.Second),
			AnalyticsURL:                         nullable.From("ANALYTICS-URL"),
			Audience:                             nullable.From([]string{"AUDIENCE-1", "AUDIENCE-2"}),
			AuthenticateServiceURL:               nullable.From("https://authenticate.example.com"),
			BindAddress:                          nullable.From("127.0.0.1:1234"),
			BootstrapServiceAccount:              nullable.From(true),
			CacheDir:                             nullable.From("CACHE-DIR"),
			ChangesetRequiredApprovalCount:       nullable.From(uint32(3)),
			CustomerID:                           nullable.From("CUSTOMER-ID"),
			DangerouslyDisableAllNamespaceChecks: nullable.From(true),
			DatabaseEncryptionKey:                nullable.From([]byte{0x01, 0x02, 0x03}),
			DatabaseEncryptionKeyFile:            nullable.From("DATABASE-ENCRYPTION-KEY-FILE"),
			DatabaseEncryptionKeyRawFile:         nullable.From("DATABASE-ENCRYPTION-KEY-RAW-FILE"),
			DatabaseURL:                          nullable.From("sqlite:///tmp/example"),
			DatabrokerServiceURLs:                nullable.From([]string{"https://databroker.example.com"}),
			DebugAddress:                         nullable.From("127.0.0.1:2345"),
			DebugConfigDump:                      nullable.From(true),
			DirectoryProvider:                    nullable.From("DIRECTORY-PROVIDER"),
			DirectoryProviderOptions:             nullable.From(map[string]any{"OPTION-1": "VALUE-1", "OPTION-2": "VALUE-2"}),
			DirectoryProviderRefreshInterval:     nullable.From(3 * time.Second),
			DirectoryProviderRefreshTimeout:      nullable.From(4 * time.Second),
			DisableFeedbackWidget:                nullable.From(true),
			DisableRemoteDiagnostics:             nullable.From(false),
			EnableSessionRecordingQuerierCache:   nullable.From(true),
			GRPCAddress:                          nullable.From("127.0.0.1:3456"),
			LicenseKey:                           nullable.From("LICENSE-KEY"),
			LicenseKeyValidateOffline:            nullable.From(true),
			LogLevel:                             nullable.From("fatal"),
			MetricsAddress:                       nullable.From("127.0.0.1:4567"),
			OverrideCertificateName:              nullable.From("OVERRIDE-CERTIFICATE-NAME"),
			PrometheusDataDir:                    nullable.From("/tmp/prometheus"),
			PrometheusListenAddress:              nullable.From("127.0.0.1:5678"),
			PrometheusScrapeInterval:             nullable.From(77 * time.Second),
			PrometheusURL:                        nullable.From("https://prometheus.example.com"),
			PublicAddress:                        nullable.From("127.0.0.1:6789"),
			SessionRecordingOptions:              nullable.From(map[string]any{"OPTION-1": "VALUE-1", "OPTION-2": "VALUE-2"}),
			SharedSecret:                         nullable.From([]byte{0xAA, 0xAB, 0xAC}),
			SharedSecretFile:                     nullable.From("SHARED-SECRET-FILE"),
			SharedSecretRawFile:                  nullable.From("SHARED-SECRET-RAW-FILE"),
			SigningKey:                           nullable.From([]byte{0xF0, 0xF1, 0xF2}),
			SigningKeyFile:                       nullable.From("SIGNING-KEY-FILE"),
			SigningKeyRawFile:                    nullable.From("SIGNING-KEY-RAW-FILE"),
			TLSCertificate:                       nullable.From([]byte{0x00, 0x01, 0x02}),
			TLSCertificateAuthority:              nullable.From([]byte{0x03, 0x04, 0x05}),
			TLSCertificateAuthorityFile:          nullable.From("TLS-CERTIFICATE-AUTHORITY-FILE"),
			TLSCertificateFile:                   nullable.From("TLS-CERTIFICATE-FILE"),
			TLSDerive:                            nullable.From("TLS-DERIVE"),
			TLSInsecureSkipVerify:                nullable.From(false),
			TLSKey:                               nullable.From([]byte{0x06, 0x07, 0x08}),
			TLSKeyFile:                           nullable.From("TLS-KEY-FILE"),
			UseStaticAssets:                      nullable.From(true),
			URL:                                  nullable.From("https://example.com"),
			ValidationMode:                       nullable.From(configpb.EnterpriseValidationMode_ENTERPRISE_VALIDATION_MODE_FULL),
		})
		options, enabled, err := buildOptions(cfg)
		assert.NoError(t, err)
		assert.True(t, enabled)
		assert.Equal(t, map[string]any{
			"administrators":                           []string{"u1", "u2", "u3"},
			"analytics_collect_interval":               "3s",
			"analytics_url":                            "ANALYTICS-URL",
			"audience":                                 []string{"AUDIENCE-1", "AUDIENCE-2"},
			"authenticate_service_url":                 "https://authenticate.example.com",
			"bind_addr":                                "127.0.0.1:1234",
			"bootstrap_service_account":                true,
			"cache_dir":                                "CACHE-DIR",
			"changeset_required_approval_count":        3,
			"customer_id":                              "CUSTOMER-ID",
			"dangerously_disable_all_namespace_checks": true,
			"database_encryption_key":                  "AQID",
			"database_encryption_key_file":             "DATABASE-ENCRYPTION-KEY-FILE",
			"database_encryption_key_raw_file":         "DATABASE-ENCRYPTION-KEY-RAW-FILE",
			"database_url":                             "sqlite:///tmp/example",
			"databroker_service_urls":                  []string{"https://databroker.example.com"},
			"debug_addr":                               "127.0.0.1:2345",
			"debug_config_dump":                        true,
			"directory_provider":                       "DIRECTORY-PROVIDER",
			"directory_provider_options":               map[string]any{"OPTION-1": "VALUE-1", "OPTION-2": "VALUE-2"},
			"directory_provider_refresh_interval":      "3s",
			"directory_provider_refresh_timeout":       "4s",
			"disable_feedback_widget":                  true,
			"disable_remote_diagnostics":               false,
			"enable_session_recording_querier_cache":   true,
			"grpc_addr":                                "127.0.0.1:3456",
			"license_key":                              "LICENSE-KEY",
			"license_key_validate_offline":             true,
			"log_level":                                "fatal",
			"metrics_addr":                             "127.0.0.1:4567",
			"override_certificate_name":                "OVERRIDE-CERTIFICATE-NAME",
			"prometheus_data_dir":                      "/tmp/prometheus",
			"prometheus_listen_addr":                   "127.0.0.1:5678",
			"prometheus_scrape_interval":               "1m17s",
			"prometheus_url":                           "https://prometheus.example.com",
			"public_addr":                              "127.0.0.1:6789",
			"session_recording_options":                map[string]any{"OPTION-1": "VALUE-1", "OPTION-2": "VALUE-2"},
			"shared_secret":                            "qqus",
			"shared_secret_file":                       "SHARED-SECRET-FILE",
			"shared_secret_raw_file":                   "SHARED-SECRET-RAW-FILE",
			"signing_key":                              "8PHy",
			"signing_key_file":                         "SIGNING-KEY-FILE",
			"signing_key_raw_file":                     "SIGNING-KEY-RAW-FILE",
			"tls_cert":                                 "AAEC",
			"tls_ca":                                   "AwQF",
			"tls_ca_file":                              "TLS-CERTIFICATE-AUTHORITY-FILE",
			"tls_cert_file":                            "TLS-CERTIFICATE-FILE",
			"tls_derive":                               "TLS-DERIVE",
			"tls_insecure_skip_verify":                 false,
			"tls_key":                                  "BgcI",
			"tls_key_file":                             "TLS-KEY-FILE",
			"url":                                      "https://example.com",
			"use_static_assets":                        true,
			"validation_mode":                          "full",
		}, options)
	})
	t.Run("saves database encryption key", func(t *testing.T) {
		cfg := config.New(config.NewDefaultOptions())
		cfg.Options.SharedKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xA0}, 32))
		cfg.Options.Enterprise = nullable.From(config.EnterpriseSettings{
			URL: nullable.From("https://example.com"),
		})
		options1, enabled, err := buildOptions(cfg)
		assert.NoError(t, err)
		assert.True(t, enabled)
		cfg.Options.SharedKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xA1}, 32))
		options2, enabled, err := buildOptions(cfg)
		assert.NoError(t, err)
		assert.True(t, enabled)
		assert.Equal(t, options1["database_encryption_key"], options2["database_encryption_key"])
	})
}
