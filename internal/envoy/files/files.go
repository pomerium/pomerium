// Package files contains files for use with envoy.
package files

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/natefinch/atomic"

	"github.com/pomerium/pomerium/internal/log"
)

const (
	embeddedEnvoyPermissions     fs.FileMode = 0o700
	embeddedDirectoryPermissions fs.FileMode = 0o755
)

var (
	embeddedFilesBaseDirectory = filepath.Join(os.TempDir(), "pomerium-embedded-files")

	extractOnce    sync.Once
	extractOutPath string
	extractErr     error
)

type embeddedEnvoyProvider struct {
}

func (embeddedEnvoyProvider) Checksum() string {
	return strings.Fields(rawChecksum)[0]
}

func (embeddedEnvoyProvider) Extract(ctx context.Context) (string, error) {
	extractOnce.Do(func() {
		// clean up our base directory before starting
		extractErr = os.RemoveAll(embeddedFilesBaseDirectory)
		if extractErr != nil {
			extractErr = fmt.Errorf("error cleaning embedded file directory: (directory=%s): %w", embeddedFilesBaseDirectory, extractErr)
			return
		}

		// create known directory base to clean at startup
		extractErr = os.MkdirAll(embeddedFilesBaseDirectory, embeddedDirectoryPermissions)
		if extractErr != nil {
			extractErr = fmt.Errorf("error creating embedded file directory: (directory=%s): %w", embeddedFilesBaseDirectory, extractErr)
			return
		}

		// build a random temp directory inside our base directory to guarantee permissions
		var tmpDir string
		tmpDir, extractErr = os.MkdirTemp(embeddedFilesBaseDirectory, "envoy-")
		if extractErr != nil {
			extractErr = fmt.Errorf("error creating embedded file tmp directory: (directory=%s): %w", embeddedFilesBaseDirectory, extractErr)
			return
		}

		extractOutPath = filepath.Join(tmpDir, "envoy")

		log.Info(ctx).Str("path", extractOutPath).Msg("extracting envoy binary")
		extractErr = atomic.WriteFile(extractOutPath, bytes.NewReader(rawBinary))
		if extractErr != nil {
			extractErr = fmt.Errorf("error extracting embedded envoy binary to temporary directory (path=%s): %w", extractOutPath, extractErr)
			return
		}

		extractErr = os.Chmod(extractOutPath, embeddedEnvoyPermissions)
		if extractErr != nil {
			extractErr = fmt.Errorf("error chmoding embedded envoy binary: %w", extractErr)
			return
		}
	})
	return extractOutPath, extractErr
}

func (embeddedEnvoyProvider) Version() string {
	return strings.TrimSpace(rawVersion)
}

// EmbeddedEnvoyProvider provides an embedded envoy binary via go:embed.
var EmbeddedEnvoyProvider = new(embeddedEnvoyProvider)
