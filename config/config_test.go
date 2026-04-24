package config_test

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func TestGenerateCatchAllCertificate(t *testing.T) {
	expected := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEILl9Nj1pmMzK/dHZ1yZcF1aPsCL0iqDsyHvIAyr4JNX+oAoGCCqGSM49
AwEHoUQDQgAEpDspy8qOG7ARSokzfO86qBnuMetrXUWhPoOU68aqr/KlsIW+KvX1
FiPqTUIoAXth7BiRbJ3gNjNEtdUV1Rtn3w==
-----END EC PRIVATE KEY-----
`
	cfg := &config.Config{Options: &config.Options{
		SharedKey: base64.StdEncoding.EncodeToString([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")),
	}}
	cert, err := cfg.GenerateCatchAllCertificate()
	require.NoError(t, err)
	key, err := cryptutil.EncodePrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	require.NoError(t, err)
	assert.Equal(t, expected, string(key))

	cfg.Options.DeriveInternalDomainCert = new("example.com")
	cert, err = cfg.GenerateCatchAllCertificate()
	require.NoError(t, err)
	key, err = cryptutil.EncodePrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	require.NoError(t, err)
	assert.Equal(t, expected, string(key))
}

func TestGenerated(t *testing.T) {
	t.Parallel()
	t.Run("json", func(t *testing.T) {
		t.Parallel()
		var dst config.GlobalOptions
		require.NoError(t, json.Unmarshal([]byte(`{"allow_upgrades":["x","y","z"]}`), &dst))
		assert.Equal(t, config.GlobalOptions{
			AllowUpgrades: nullable.From([]string{"x", "y", "z"}),
		}, dst)
		require.NoError(t, json.Unmarshal([]byte(`{}`), &dst))
		assert.Equal(t, config.GlobalOptions{
			AllowUpgrades: nullable.From([]string{"x", "y", "z"}),
		}, dst, "should preserve existing value")
	})
	t.Run("viper", func(t *testing.T) {
		t.Parallel()
		fp := filepath.Join(t.TempDir(), "config.json")
		require.NoError(t, os.WriteFile(fp, []byte(`{"allow_upgrades":["x","y","z"]}`), 0o600))
		v := viper.New()
		v.AddConfigPath(filepath.Dir(fp))
		require.NoError(t, v.ReadInConfig())
		var dst config.GlobalOptions
		require.NoError(t, v.Unmarshal(&dst, config.ViperPolicyHooks))
		assert.Equal(t, config.GlobalOptions{
			AllowUpgrades: nullable.From([]string{"x", "y", "z"}),
		}, dst)
	})
	t.Run("yaml", func(t *testing.T) {
		t.Parallel()
		var dst config.GlobalOptions
		err := yaml.Unmarshal([]byte(`
allow_upgrades:
  - x
  - y
  - z
`), &dst)
		require.NoError(t, err)
		assert.Equal(t, config.GlobalOptions{
			AllowUpgrades: nullable.From([]string{"x", "y", "z"}),
		}, dst)
	})
}
