package netutil

import (
	"os"
	"path/filepath"
	"runtime"
)

// GetUnixSocketPath returns a unix socket path for the current operating
// system.
func GetUnixSocketPath(name string) string {
	return GetUnixSocketPathForOS(runtime.GOOS, name)
}

// GetUnixSocketPathForOS returns a unix socket path for the given
// operating system. If the POMERIUM_SOCKET_DIRECTORY environment variable
// is set, that will be where the socket is stored. Otherwise, on linux the
// abstract socket namespace will be used, and everywhere else os.TempDir()
// will be used.
func GetUnixSocketPathForOS(goos string, name string) string {
	if v := os.Getenv("POMERIUM_SOCKET_DIRECTORY"); v != "" {
		return filepath.Join(v, name)
	} else if goos == "linux" {
		return "@" + name
	}
	return filepath.Join(os.TempDir(), name)
}
