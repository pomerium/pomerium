package file_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/storage/file"
)

func TestOpenPebbleDB(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.SkipNow()
	}

	t.Run("empty", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "test")
		t.Setenv("XDG_DATA_HOME", dir)
		db, err := file.OpenPebbleDB("")
		require.NoError(t, err)
		assert.NoError(t, db.Close())
		_, err = os.Stat(filepath.Join(dir, "pomerium", "databroker", "MANIFEST-000001"))
		require.NoError(t, err)
	})
	t.Run("bare", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "test")
		t.Setenv("XDG_DATA_HOME", dir)
		db, err := file.OpenPebbleDB("file:")
		require.NoError(t, err)
		assert.NoError(t, db.Close())
		_, err = os.Stat(filepath.Join(dir, "pomerium", "databroker", "MANIFEST-000001"))
		require.NoError(t, err)
	})
	t.Run("empty path", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "test")
		t.Setenv("XDG_DATA_HOME", dir)
		db, err := file.OpenPebbleDB("file://")
		require.NoError(t, err)
		assert.NoError(t, db.Close())
		_, err = os.Stat(filepath.Join(dir, "pomerium", "databroker", "MANIFEST-000001"))
		require.NoError(t, err)
	})
	t.Run("absolute path", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "test")
		t.Setenv("XDG_DATA_HOME", dir)
		db, err := file.OpenPebbleDB(dir)
		require.NoError(t, err)
		assert.NoError(t, db.Close())
		_, err = os.Stat(filepath.Join(dir, "MANIFEST-000001"))
		require.NoError(t, err)
	})
}
