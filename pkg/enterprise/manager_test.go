package enterprise

import (
	"bytes"
	"encoding/base64"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
)

func TestBuildOptions(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
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
		cfg.Options.Enterprise = map[string]any{
			"url": "https://example.com",
		}
		options, enabled, err := buildOptions(cfg)
		assert.NoError(t, err)
		assert.True(t, enabled)
		assert.Equal(t, map[string]any{
			"cache_dir":               filepath.Join(dir, "cache", "pomerium", "enterprise-console"),
			"database_encryption_key": "oKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKA=",
			"database_url":            "sqlite://" + path.Join(dir, "data", "pomerium", "enterprise-console", "data.sqlite"),
			"databroker_service_url":  "http://localhost:5443",
			"prometheus_data_dir":     filepath.Join(dir, "data", "pomerium", "enterprise-console", "prometheus"),
			"url":                     "https://example.com",
			"shared_secret":           "oKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKA=",
			"signing_key":             "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUlSMHFBTklRUlJvNTNyaFpIRGwyRG9iYXFUMnlXMk0xWlgvOHdyQ05wUFlvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFT0tSS2tkRmZjY2FRcVFqaUEvQ0t1NHZTM3IyUVVQZUtoS2ZxbkxiVFRic09PcjRGN1h3UQovYWpmWFdVcFhUUWFQdDZncW1oeGREMHp0VFVQYm10NUp3PT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo=",
			"validation_mode":         "static",
		}, options)
	})
}
