package filemgr

import (
	"os"
	"path/filepath"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/stretchr/testify/assert"
)

func Test(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	t.Run("bytes", func(t *testing.T) {
		mgr := NewManager(WithCacheDir(dir))
		ds := mgr.BytesDataSource("test.txt", []byte{1, 2, 3, 4, 5})
		assert.Equal(t, &envoy_config_core_v3.DataSource{
			Specifier: &envoy_config_core_v3.DataSource_Filename{
				Filename: filepath.Join(dir, "test-31443434314d425355414b4539.txt"),
			},
		}, ds)
		mgr.ClearCache()
	})

	t.Run("file", func(t *testing.T) {
		tmpFilePath := filepath.Join(dir, "test.txt")
		_ = os.WriteFile(tmpFilePath, []byte("TEST1"), 0o777)

		mgr := NewManager(WithCacheDir(dir))

		ds := mgr.FileDataSource(tmpFilePath)
		assert.Equal(t, &envoy_config_core_v3.DataSource{
			Specifier: &envoy_config_core_v3.DataSource_Filename{
				Filename: filepath.Join(dir, "test-3246454c394658475133414f35.txt"),
			},
		}, ds)

		_ = os.WriteFile(tmpFilePath, []byte("TEST2"), 0o777)

		ds = mgr.FileDataSource(tmpFilePath)
		assert.Equal(t, &envoy_config_core_v3.DataSource{
			Specifier: &envoy_config_core_v3.DataSource_Filename{
				Filename: filepath.Join(dir, "test-33343439385257475847375443.txt"),
			},
		}, ds)

		mgr.ClearCache()
	})
}
