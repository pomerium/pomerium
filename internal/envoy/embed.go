package envoy

import (
	"context"
	_ "embed" // for embedded files
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/natefinch/atomic"
	resources "gopkg.in/cookieo9/resources-go.v2"

	"github.com/pomerium/pomerium/internal/log"
)

const (
	embeddedEnvoyPermissions     fs.FileMode = 0o700
	embeddedDirectoryPermissions fs.FileMode = 0o755
)

var embeddedFilesBaseDirectory = filepath.Join(os.TempDir(), "pomerium-embedded-files")

func extractEmbeddedEnvoy(ctx context.Context) (outPath string, err error) {
	exePath, err := resources.ExecutablePath()
	if err != nil {
		return "", fmt.Errorf("error finding executable path: %w", err)
	}
	bundle, err := resources.OpenZip(exePath)
	if err != nil {
		return "", fmt.Errorf("error opening binary zip file: %w", err)
	}
	defer bundle.Close()

	rc, err := bundle.Open("envoy")
	if err != nil {
		return "", fmt.Errorf("error opening embedded envoy binary: %w", err)
	}
	defer rc.Close()

	// clean up our base directory before starting
	err = os.RemoveAll(embeddedFilesBaseDirectory)
	if err != nil {
		return "", fmt.Errorf("error cleaning embedded file directory: (directory=%s): %w", embeddedFilesBaseDirectory, err)
	}

	// create known directory base to clean at startup
	err = os.MkdirAll(embeddedFilesBaseDirectory, embeddedDirectoryPermissions)
	if err != nil {
		return "", fmt.Errorf("error creating embedded file directory: (directory=%s): %w", embeddedFilesBaseDirectory, err)
	}

	// build a random temp directory inside our base directory to guarantee permissions
	tmpDir, err := os.MkdirTemp(embeddedFilesBaseDirectory, "envoy-")
	outPath = filepath.Join(tmpDir, "envoy")

	log.Info(ctx).Str("path", outPath).Msg("extracting envoy binary")
	err = atomic.WriteFile(outPath, rc)
	if err != nil {
		return "", fmt.Errorf("error extracting embedded envoy binary to temporary directory (path=%s): %w", outPath, err)
	}

	err = os.Chmod(outPath, embeddedEnvoyPermissions)
	if err != nil {
		return "", fmt.Errorf("error chmoding embedded envoy binary: %w", err)
	}

	return outPath, nil
}
