package config

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFileWatcherSource(t *testing.T) {
	ctx := context.Background()

	tmpdir := t.TempDir()

	err := os.WriteFile(filepath.Join(tmpdir, "example.txt"), []byte{1}, 0o600)
	if !assert.NoError(t, err) {
		return
	}

	err = os.WriteFile(filepath.Join(tmpdir, "kubernetes-example.txt"), []byte{2}, 0o600)
	if !assert.NoError(t, err) {
		return
	}

	ssrc := NewStaticSource(&Config{
		Options: &Options{
			CAFile: filepath.Join(tmpdir, "example.txt"),
			Policies: []Policy{{
				KubernetesServiceAccountTokenFile: filepath.Join(tmpdir, "kubernetes-example.txt"),
			}},
		},
	})

	src := NewFileWatcherSource(ctx, ssrc)
	var closeOnce sync.Once
	ch := make(chan struct{})
	src.OnConfigChange(context.Background(), func(ctx context.Context, cfg *Config) {
		closeOnce.Do(func() {
			close(ch)
		})
	})

	err = os.WriteFile(filepath.Join(tmpdir, "example.txt"), []byte{1, 2}, 0o600)
	if !assert.NoError(t, err) {
		return
	}

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Error("expected OnConfigChange to be fired after modifying a file")
	}

	err = os.WriteFile(filepath.Join(tmpdir, "kubernetes-example.txt"), []byte{2, 3}, 0o600)
	if !assert.NoError(t, err) {
		return
	}

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Error("expected OnConfigChange to be fired after modifying a policy file")
	}

	ssrc.SetConfig(ctx, &Config{
		Options: &Options{
			CAFile: filepath.Join(tmpdir, "example.txt"),
		},
	})

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Error("expected OnConfigChange to be fired after triggering a change to the underlying source")
	}
}
