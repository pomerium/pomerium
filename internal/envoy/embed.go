package envoy

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/natefinch/atomic"
	resources "gopkg.in/cookieo9/resources-go.v2"
)

var embeddedFilesDirectory = filepath.Join(os.TempDir(), "pomerium-embedded-files")

func extractEmbeddedEnvoy() (outPath string, err error) {
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

	err = os.MkdirAll(embeddedFilesDirectory, 0o755)
	if err != nil {
		return "", fmt.Errorf("error creating embedded file directory: (directory=%s): %w", embeddedFilesDirectory, err)
	}

	outPath = filepath.Join(embeddedFilesDirectory, "envoy")

	// skip extraction if we already have it
	var zfi os.FileInfo
	if zf, ok := rc.(interface{ FileInfo() os.FileInfo }); ok {
		zfi = zf.FileInfo()
		if fi, e := os.Stat(outPath); e == nil {
			if fi.Size() == zfi.Size() && fi.ModTime() == zfi.ModTime() {
				return outPath, nil
			}
		}
	}

	err = atomic.WriteFile(outPath, rc)
	if err != nil {
		return "", fmt.Errorf("error extracting embedded envoy binary to temporary directory (path=%s): %w", outPath, err)
	}

	err = os.Chmod(outPath, 0o755)
	if err != nil {
		return "", fmt.Errorf("error chmoding embedded envoy binary: %w", err)
	}

	if zfi != nil {
		_ = os.Chtimes(outPath, zfi.ModTime(), zfi.ModTime())
	}

	return outPath, nil
}
