package envoyconfig

import (
	"os"
	"path/filepath"
	"runtime"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
)

var (
	// EnvoyAdminAddressSockName is the name of the pomerium envoy admin socket.
	EnvoyAdminAddressSockName = "pomerium-envoy-admin.sock"
	envoyAdminClusterName     = "pomerium-envoy-admin"
)

// GetPipe returns a pipe for use with envoy for the current operating system.
func GetPipe(name string) *envoy_config_core_v3.Pipe {
	return GetPipeForOS(runtime.GOOS, name)
}

// GetPipeForOS returns a pipe for use with envoy for the given operating system.
// If the POMERIUM_SOCKET_DIRECTORY environment variable is set, that will be
// where the socket is stored. Otherwise, on linux the abstract socket namespace
// will be used, and everywhere else os.TempDir() will be used.
func GetPipeForOS(goos string, name string) *envoy_config_core_v3.Pipe {
	pipe := new(envoy_config_core_v3.Pipe)
	if v := os.Getenv("POMERIUM_SOCKET_DIRECTORY"); v != "" {
		pipe.Path = filepath.Join(v, name)
		pipe.Mode = 0o600
	} else if goos == "linux" {
		pipe.Path = "@" + name
	} else {
		pipe.Path = filepath.Join(os.TempDir(), name)
		pipe.Mode = 0o600
	}
	return pipe
}
