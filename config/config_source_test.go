package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileWatcherSource(t *testing.T) {
	tmpdir := t.TempDir()

	err := os.WriteFile(filepath.Join(tmpdir, "example.txt"), []byte{1}, 0o600)
	if !assert.NoError(t, err) {
		return
	}

	err = os.WriteFile(filepath.Join(tmpdir, "kubernetes-example.txt"), []byte{2}, 0o600)
	if !assert.NoError(t, err) {
		return
	}

	newTest := func(enabled bool) func(*testing.T) {
		return func(t *testing.T) {
			ssrc := NewStaticSource(&Config{
				Options: &Options{
					CAFile: filepath.Join(tmpdir, "example.txt"),
					Policies: []Policy{{
						KubernetesServiceAccountTokenFile: filepath.Join(tmpdir, "kubernetes-example.txt"),
					}},
					RuntimeFlags: map[RuntimeFlag]bool{
						RuntimeFlagConfigHotReload: enabled,
					},
				},
			})

			src := NewFileWatcherSource(context.Background(), ssrc)
			ch := make(chan struct{}, 10)
			src.OnConfigChange(context.Background(), func(_ context.Context, _ *Config) {
				ch <- struct{}{}
			})

			err := os.WriteFile(filepath.Join(tmpdir, "example.txt"), []byte{1, 2}, 0o600)
			if !assert.NoError(t, err) {
				return
			}

			select {
			case <-ch:
				if !enabled {
					t.Error("expected OnConfigChange not to be fired after modifying a file")
				}
			case <-time.After(time.Second):
				if enabled {
					t.Error("expected OnConfigChange to be fired after modifying a file")
				}
			}

			require.Empty(t, ch, "expected exactly one OnConfigChange event")

			err = os.WriteFile(filepath.Join(tmpdir, "kubernetes-example.txt"), []byte{2, 3}, 0o600)
			if !assert.NoError(t, err) {
				return
			}

			select {
			case <-ch:
				if !enabled {
					t.Error("expected OnConfigChange not to be fired after modifying a file")
				}
			case <-time.After(time.Second):
				if enabled {
					t.Error("expected OnConfigChange to be fired after modifying a policy file")
				}
			}

			require.Empty(t, ch, "expected exactly one OnConfigChange event")

			ssrc.SetConfig(context.Background(), &Config{
				Options: &Options{
					CAFile: filepath.Join(tmpdir, "example.txt"),
				},
			})

			select {
			case <-ch:
			case <-time.After(time.Second):
				if enabled {
					t.Error("expected OnConfigChange to be fired after triggering a change to the underlying source")
				}
			}

			require.Empty(t, ch, "expected exactly one OnConfigChange event")
		}
	}

	t.Run("Hot Reload Enabled", newTest(true))
	t.Run("Hot Reload Disabled", newTest(false))
}

func TestFileOrEnvironmentSource(t *testing.T) {
	tmpdir := t.TempDir()

	err := os.WriteFile(filepath.Join(tmpdir, "example.txt"), []byte{1}, 0o600)
	if !assert.NoError(t, err) {
		return
	}

	err = os.WriteFile(filepath.Join(tmpdir, "kubernetes-example.txt"), []byte{2}, 0o600)
	if !assert.NoError(t, err) {
		return
	}

	newTest := func(enabled bool) func(*testing.T) {
		return func(t *testing.T) {
			initialConfigYaml := fmt.Sprintf(`
certificate_authority_file: %s
policy:
- from: https://foo
  to: https://bar
  kubernetes_service_account_token_file: %s
codec_type: auto
runtime_flags:
  config_hot_reload: %t
`,
				filepath.Join(tmpdir, "example.txt"),
				filepath.Join(tmpdir, "kubernetes-example.txt"),
				enabled,
			)
			configFilePath := filepath.Join(tmpdir, "config.yaml")
			err := os.WriteFile(configFilePath, []byte(initialConfigYaml), 0o600)
			require.NoError(t, err)

			var src Source
			src, err = NewFileOrEnvironmentSource(context.Background(), configFilePath, "")
			require.NoError(t, err)
			src = NewFileWatcherSource(context.Background(), src)

			ch := make(chan struct{}, 10)
			src.OnConfigChange(context.Background(), func(_ context.Context, _ *Config) {
				ch <- struct{}{}
			})

			err = os.WriteFile(filepath.Join(tmpdir, "example.txt"), []byte{1, 2}, 0o600)
			require.NoError(t, err)

			select {
			case <-ch:
				if !enabled {
					t.Error("expected OnConfigChange not to be fired after modifying a file")
				}
			case <-time.After(time.Second):
				if enabled {
					t.Error("expected OnConfigChange to be fired after modifying a file")
				}
			}

			require.Empty(t, ch, "expected exactly one OnConfigChange event")

			err = os.WriteFile(filepath.Join(tmpdir, "kubernetes-example.txt"), []byte{2, 3}, 0o600)
			if !assert.NoError(t, err) {
				return
			}

			select {
			case <-ch:
				if !enabled {
					t.Error("expected OnConfigChange not to be fired after modifying a file")
				}
			case <-time.After(time.Second):
				if enabled {
					t.Error("expected OnConfigChange to be fired after modifying a policy file")
				}
			}

			require.Empty(t, ch, "expected exactly one OnConfigChange event")

			// the file watcher checks modification time, not contents
			err = os.Chtimes(configFilePath, time.Now(), time.Now())
			require.NoError(t, err)

			select {
			case <-ch:
				if !enabled {
					t.Error("expected OnConfigChange not to be fired after triggering a change to the underlying source")
				}
			case <-time.After(time.Second):
				if enabled {
					t.Error("expected OnConfigChange to be fired after triggering a change to the underlying source")
				}
			}

			require.Empty(t, ch, "expected exactly one OnConfigChange event")
		}
	}

	t.Run("Hot Reload Enabled", newTest(true))
	t.Run("Hot Reload Disabled", newTest(false))
}
