package envoy

import (
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

const (
	ownerRX              = os.FileMode(0o500)
	maxExpandedEnvoySize = 2 * 1024 * 1024 * 1024 // 2GB
	envoyPrefix          = "pomerium-envoy"
)

type hashReader struct {
	hash.Hash
	r io.Reader
}

func (hr *hashReader) Read(p []byte) (n int, err error) {
	n, err = hr.r.Read(p)
	_, _ = hr.Write(p[:n])
	return n, err
}

var (
	setupLock          sync.Mutex
	setupDone          bool
	setupFullEnvoyPath string
	setupErr           error
)

// Extract extracts envoy binary and returns its location
func Extract() (fullEnvoyPath string, err error) {
	setupLock.Lock()
	defer setupLock.Unlock()

	// if we've extract at least once, and the file we previously extracted no longer exists, force a new extraction
	if setupFullEnvoyPath != "" {
		if _, err := os.Stat(setupFullEnvoyPath); os.IsNotExist(err) {
			setupDone = false
		}
	}
	if setupDone {
		return setupFullEnvoyPath, setupErr
	}

	tmpDir := os.TempDir()

	cleanTempDir(tmpDir)
	dir, err := os.MkdirTemp(tmpDir, envoyPrefix)
	if err != nil {
		setupErr = fmt.Errorf("envoy: failed making temporary working dir: %w", err)
		return setupFullEnvoyPath, setupErr
	}
	setupFullEnvoyPath = filepath.Join(dir, "envoy")

	err = extract(setupFullEnvoyPath)
	if err != nil {
		setupErr = fmt.Errorf("envoy: failed to extract embedded envoy binary: %w", err)
		return setupFullEnvoyPath, setupErr
	}

	setupDone = true
	return setupFullEnvoyPath, setupErr
}

func cleanTempDir(tmpDir string) {
	d, err := os.Open(tmpDir)
	if err != nil {
		log.Error().Msg("envoy: failed to open temp directory for clean up")
		return
	}
	defer d.Close()

	fs, err := d.Readdir(-1)
	if err != nil {
		log.Error().Msg("envoy: failed to read files in temporary directory")
		return
	}

	for _, f := range fs {
		if f.IsDir() && strings.HasPrefix(f.Name(), envoyPrefix) {
			err := os.RemoveAll(filepath.Join(tmpDir, f.Name()))
			if err != nil {
				log.Error().Err(err).Msg("envoy: failed to delete previous extracted envoy")
			}
		}
	}
}
