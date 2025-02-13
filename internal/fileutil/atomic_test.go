package fileutil_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/fileutil"
)

func TestWriteFileAtomically(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	require.NoError(t, fileutil.WriteFileAtomically(filepath.Join(dir, "temp1.txt"), []byte("TEST"), 0o600))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	names := make([]string, len(entries))
	for i := range entries {
		names[i] = entries[i].Name()
	}

	assert.Equal(t, []string{"temp1.txt"}, names)
}
