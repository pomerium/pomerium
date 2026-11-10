//go:build debug_local_envoy

package envoy

import (
	"os"
	"path/filepath"
)

var DebugLocalEnvoyPath string

func extract(dstName string) (err error) {
	if DebugLocalEnvoyPath == "" {
		panic("DebugLocalEnvoyPath not set")
	}
	fullPath, err := filepath.EvalSymlinks(DebugLocalEnvoyPath)
	if err != nil {
		panic(err)
	}
	return os.Symlink(fullPath, dstName)
}
