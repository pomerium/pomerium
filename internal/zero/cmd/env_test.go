package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_getToken(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		assert.Equal(t, "", getToken(""))
	})
	t.Run("env", func(t *testing.T) {
		t.Setenv("POMERIUM_ZERO_TOKEN", "FROM_ENV")
		assert.Equal(t, "FROM_ENV", getToken(""))
	})
	t.Run("json", func(t *testing.T) {
		fp := filepath.Join(t.TempDir(), "config.json")
		require.NoError(t, os.WriteFile(fp, []byte(`{
			"pomerium_zero_token": "FROM_JSON"
		}`), 0o644))
		assert.Equal(t, "FROM_JSON", getToken(fp))
	})
	t.Run("yaml", func(t *testing.T) {
		fp := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(fp, []byte(`
pomerium_zero_token: FROM_YAML
`), 0o644))
		assert.Equal(t, "FROM_YAML", getToken(fp))
	})
	t.Run("toml", func(t *testing.T) {
		fp := filepath.Join(t.TempDir(), "config.toml")
		require.NoError(t, os.WriteFile(fp, []byte(`
pomerium_zero_token = "FROM_TOML"
`), 0o644))
		assert.Equal(t, "FROM_TOML", getToken(fp))
	})
}
