package envoy

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/natefinch/atomic"

	"github.com/pomerium/pomerium/internal/envoy/files"
	"github.com/pomerium/pomerium/internal/log"
)

const (
	embeddedEnvoyPermissions     fs.FileMode = 0o700
	embeddedDirectoryPermissions fs.FileMode = 0o755
)

var (
	embeddedFilesBaseDirectory = filepath.Join(os.TempDir(), "pomerium-embedded-files")
	extractEmbeddedEnvoyOnce   sync.Once
)

func extractEmbeddedEnvoy(ctx context.Context) (outPath string, err error) {
	extractEmbeddedEnvoyOnce.Do(func() {
		// clean up our base directory before starting
		err = os.RemoveAll(embeddedFilesBaseDirectory)
		if err != nil {
			err = fmt.Errorf("error cleaning embedded file directory: (directory=%s): %w", embeddedFilesBaseDirectory, err)
			return
		}

		// create known directory base to clean at startup
		err = os.MkdirAll(embeddedFilesBaseDirectory, embeddedDirectoryPermissions)
		if err != nil {
			err = fmt.Errorf("error creating embedded file directory: (directory=%s): %w", embeddedFilesBaseDirectory, err)
			return
		}

		// build a random temp directory inside our base directory to guarantee permissions
		var tmpDir string
		tmpDir, err = os.MkdirTemp(embeddedFilesBaseDirectory, "envoy-")
		if err != nil {
			err = fmt.Errorf("error creating embedded file tmp directory: (directory=%s): %w", embeddedFilesBaseDirectory, err)
			return
		}

		outPath = filepath.Join(tmpDir, "envoy")

		log.Info(ctx).Str("path", outPath).Msg("extracting envoy binary")
		err = atomic.WriteFile(outPath, bytes.NewReader(files.Binary()))
		if err != nil {
			err = fmt.Errorf("error extracting embedded envoy binary to temporary directory (path=%s): %w", outPath, err)
			return
		}

		err = os.Chmod(outPath, embeddedEnvoyPermissions)
		if err != nil {
			err = fmt.Errorf("error chmoding embedded envoy binary: %w", err)
			return
		}
	})
	return outPath, err
}
