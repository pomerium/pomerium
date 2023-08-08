package bootstrap_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/zero/bootstrap"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	cluster_api "github.com/pomerium/zero-sdk/cluster"
)

func TestFile(t *testing.T) {
	cipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
	require.NoError(t, err)

	txt := "test"
	src := cluster_api.BootstrapConfig{
		DatabrokerStorageConnection: &txt,
	}

	fd, err := os.CreateTemp(t.TempDir(), "test.data")
	require.NoError(t, err)
	require.NoError(t, fd.Close())

	require.NoError(t, bootstrap.SaveBootstrapConfigToFile(&src, fd.Name(), cipher))

	dst, err := bootstrap.LoadBootstrapConfigFromFile(fd.Name(), cipher)
	require.NoError(t, err)

	require.Equal(t, src, *dst)
}
