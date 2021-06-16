package config

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestFileWatcherSource(t *testing.T) {
	ctx := context.Background()

	tmpdir := filepath.Join(os.TempDir(), uuid.New().String())
	err := os.MkdirAll(tmpdir, 0o755)
	if !assert.NoError(t, err) {
		return
	}

	err = ioutil.WriteFile(filepath.Join(tmpdir, "example.txt"), []byte{1, 2, 3, 4}, 0o600)
	if !assert.NoError(t, err) {
		return
	}

	ssrc := NewStaticSource(&Config{
		Options: &Options{
			CAFile: filepath.Join(tmpdir, "example.txt"),
		},
	})

	src := NewFileWatcherSource(context.Background(), ssrc)
	var closeOnce sync.Once
	ch := make(chan struct{})
	src.OnConfigChange(context.Background(), func(ctx context.Context, cfg *Config) {
		closeOnce.Do(func() {
			close(ch)
		})
	})

	err = ioutil.WriteFile(filepath.Join(tmpdir, "example.txt"), []byte{5, 6, 7, 8}, 0o600)
	if !assert.NoError(t, err) {
		return
	}

	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Error("expected OnConfigChange to be fired after modifying a file")
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
