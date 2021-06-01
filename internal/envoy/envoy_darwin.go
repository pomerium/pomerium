// +build darwin

package envoy

import (
	"context"
	"runtime"
	"syscall"

	"github.com/pomerium/pomerium/internal/log"
)

var sysProcAttr = &syscall.SysProcAttr{
	Setpgid: true,
}

func (srv *Server) runProcessCollector(ctx context.Context) {}

func (srv *Server) prepareRunEnvoyCommand(ctx context.Context, sharedArgs []string) (exePath string, args []string) {
	if srv.cmd != nil && srv.cmd.Process != nil {
		log.Info(ctx).Msg("envoy: terminating previous envoy process")
		_ = srv.cmd.Process.Kill()
	}

	args = make([]string, len(sharedArgs))
	copy(args, sharedArgs)

	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		// until m1 macs are supported by envoy, fallback to x86 and use rosetta
		return "arch", append([]string{"-x86_64", srv.envoyPath}, args...)
	}

	return srv.envoyPath, args
}
