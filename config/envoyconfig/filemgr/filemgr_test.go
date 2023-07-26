package filemgr

import (
	"os"
	"path/filepath"
	"testing"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/stretchr/testify/assert"
)

func Test(t *testing.T) {
	dir := t.TempDir()

	t.Run("bytes", func(t *testing.T) {
		mgr := NewManager(WithCacheDir(dir))
		ds := mgr.BytesDataSource("test.txt", []byte{1, 2, 3, 4, 5})
		assert.Equal(t, &envoy_config_core_v3.DataSource{
			Specifier: &envoy_config_core_v3.DataSource_Filename{
				Filename: filepath.Join(dir, "test-353354494b53534a5538435652584d594a5759394d43484f38514b34594b4b524b34515339593249344e4238474a5436414b.txt"),
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
				Filename: filepath.Join(dir, "test-34514f59593332445a5649504230484142544c515057383944383730554833564d32574836354654585954304e424f464336.txt"),
			},
		}, ds)

		_ = os.WriteFile(tmpFilePath, []byte("TEST2"), 0o777)

		ds = mgr.FileDataSource(tmpFilePath)
		assert.Equal(t, &envoy_config_core_v3.DataSource{
			Specifier: &envoy_config_core_v3.DataSource_Filename{
				Filename: filepath.Join(dir, "test-32564e4457304430393559364b5747373138584f484f5a51334d365758584b47364b555a4c444849513241513457323259.txt"),
			},
		}, ds)

		mgr.ClearCache()
	})
}
