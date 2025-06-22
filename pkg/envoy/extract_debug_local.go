//go:build debug_local_envoy

package envoy

import (
	"os"
	"path/filepath"

	"github.com/pomerium/pomerium/pkg/envoy/files"
)

var DebugLocalEnvoyPath string

func init() {
	files.SetFiles(nil, "<external> _", "")
}

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
