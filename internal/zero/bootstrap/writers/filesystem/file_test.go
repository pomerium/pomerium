package filesystem_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/zero/bootstrap"
	"github.com/pomerium/pomerium/internal/zero/bootstrap/writers"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	cluster_api "github.com/pomerium/pomerium/pkg/zero/cluster"
)

func TestFileWriter(t *testing.T) {
	cipher, err := cryptutil.NewAEADCipher(cryptutil.NewKey())
	require.NoError(t, err)

	txt := "test"
	src := cluster_api.BootstrapConfig{
		DatabrokerStorageConnection: &txt,
	}

	fd, err := os.CreateTemp(t.TempDir(), "test.data")
	require.NoError(t, err)
	require.NoError(t, fd.Close())

	writer, err := writers.NewForURI(fmt.Sprintf("file://%s", fd.Name()))
	require.NoError(t, err)

	writer = writer.WithOptions(writers.ConfigWriterOptions{
		Cipher: cipher,
	})
	require.NoError(t, bootstrap.SaveBootstrapConfig(t.Context(), writer, &src))

	dst, err := bootstrap.LoadBootstrapConfigFromFile(fd.Name(), cipher)
	require.NoError(t, err)

	require.Equal(t, src, *dst)
}

func TestNewForURI(t *testing.T) {
	for _, tc := range []struct {
		uri string
		err string
	}{
		{
			uri: "file:///path/to/file",
		},
		{
			uri: "file://path/to/file",
			err: `invalid file uri "file://path/to/file" (did you mean "file:///path/to/file"?)`,
		},
	} {
		w, err := writers.NewForURI(tc.uri)
		if tc.err == "" {
			assert.NoError(t, err)
			assert.NotNil(t, w)
		} else {
			assert.EqualError(t, err, tc.err)
			assert.Nil(t, w)
		}
	}
}
