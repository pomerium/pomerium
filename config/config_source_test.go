package config

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/log"
)

func TestFileWatcherSource(t *testing.T) {
	ctx := context.Background()

	// capture logs
	var logOutput bytes.Buffer
	logger := zerolog.New(io.MultiWriter(zerolog.SyncWriter(&logOutput), zerolog.NewTestWriter(t)))
	originalLogger := log.Logger()
	log.SetLogger(&logger)
	t.Cleanup(func() {
		log.SetLogger(originalLogger)
	})

	tmpdir := t.TempDir()

	err := os.WriteFile(filepath.Join(tmpdir, "example.txt"), []byte{1}, 0o600)
	if !assert.NoError(t, err) {
		return
	}

	err = os.WriteFile(filepath.Join(tmpdir, "kubernetes-example.txt"), []byte{2}, 0o600)
	if !assert.NoError(t, err) {
		return
	}

	testCertFileRef := "./testdata/example-cert.pem"
	testKeyFileRef := "./testdata/example-key.pem"
	testCertFile, _ := os.ReadFile(testCertFileRef)
	testKeyFile, _ := os.ReadFile(testKeyFileRef)
	testCertAsBase64 := base64.StdEncoding.EncodeToString(testCertFile)
	testKeyAsBase64 := base64.StdEncoding.EncodeToString(testKeyFile)

	ssrc := NewStaticSource(&Config{
		Options: &Options{
			CertificateFiles: []certificateFilePair{{
				CertFile: testCertAsBase64,
				KeyFile:  testKeyAsBase64,
			}},
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

	assert.NotContains(t, logOutput.String(), "failed to add file to polling-based file watcher")
}
