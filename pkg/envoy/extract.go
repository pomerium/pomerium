package envoy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pomerium/pomerium/pkg/envoy/files"
)

const (
	ownerRX              = os.FileMode(0o500)
	maxExpandedEnvoySize = 1 << 30
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

	dir, err := os.MkdirTemp(os.TempDir(), "pomerium-envoy")
	if err != nil {
		setupErr = fmt.Errorf("envoy: failed making temporary working dir: %w", err)
		return
	}
	setupFullEnvoyPath = filepath.Join(dir, "envoy")

	err = extract(setupFullEnvoyPath)
	if err != nil {
		setupErr = fmt.Errorf("envoy: failed to extract embedded envoy binary: %w", err)
		return
	}

	setupDone = true
	return setupFullEnvoyPath, setupErr
}

func extract(dstName string) (err error) {
	checksum, err := hex.DecodeString(strings.Fields(files.Checksum())[0])
	if err != nil {
		return fmt.Errorf("checksum %s: %w", files.Checksum(), err)
	}

	hr := &hashReader{
		Hash: sha256.New(),
		r:    bytes.NewReader(files.Binary()),
	}

	dst, err := os.OpenFile(dstName, os.O_CREATE|os.O_WRONLY, ownerRX)
	if err != nil {
		return err
	}
	defer func() { err = dst.Close() }()

	if _, err = io.Copy(dst, io.LimitReader(hr, maxExpandedEnvoySize)); err != nil {
		return err
	}

	sum := hr.Sum(nil)
	if !bytes.Equal(sum, checksum) {
		return fmt.Errorf("expected %x, got %x checksum", checksum, sum)
	}
	return nil
}
