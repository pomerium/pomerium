package envoy

import (
	"io/fs"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClean(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	d1, err := os.MkdirTemp(tmpDir, envoyPrefix) //nolint:usetesting
	require.NoError(t, err)
	d2, err := os.MkdirTemp(tmpDir, envoyPrefix) //nolint:usetesting
	require.NoError(t, err)
	d3, err := os.MkdirTemp(tmpDir, envoyPrefix) //nolint:usetesting
	require.NoError(t, err)

	cleanTempDir(tmpDir)

	_, err = os.Stat(d1)
	assert.ErrorIs(t, err, fs.ErrNotExist)
	_, err = os.Stat(d2)
	assert.ErrorIs(t, err, fs.ErrNotExist)
	_, err = os.Stat(d3)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}
