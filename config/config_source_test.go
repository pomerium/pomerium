package config

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestFileWatcherSource(t *testing.T) {
	tmpdir := filepath.Join(os.TempDir(), uuid.New().String())
	err := os.MkdirAll(tmpdir, 0o755)
	if !assert.NoError(t, err) {
		return
	}

	err = ioutil.WriteFile(filepath.Join(tmpdir, "example.txt"), []byte{1, 2, 3, 4}, 0o600)
	if !assert.NoError(t, err) {
		return
	}

	src := NewFileWatcherSource(NewStaticSource(&Config{
		Options: &Options{
			CAFile: filepath.Join(tmpdir, "example.txt"),
		},
	}))
	ch := make(chan struct{})
	src.OnConfigChange(func(cfg *Config) {
		close(ch)
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
}
