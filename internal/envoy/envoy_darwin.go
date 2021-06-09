// +build darwin

package envoy

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/pomerium/pomerium/internal/log"
)

var sysProcAttr = &syscall.SysProcAttr{
	Setpgid: true,
}

// Command creates an exec.Cmd using the embedded envoy binary.
func Command(ctx context.Context, args ...string) (*exec.Cmd, error) {
	fullEnvoyPath, err := setup()
	if err != nil {
		return nil, err
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		// until m1 macs are supported by envoy, fallback to x86 and use rosetta
		cmd = exec.CommandContext(ctx, "arch", append([]string{"-x86_64", fullEnvoyPath}, args...)...)
	} else {
		cmd = exec.CommandContext(ctx, fullEnvoyPath, args...)
	}
	cmd.Dir = filepath.Dir(fullEnvoyPath)

	return cmd, nil
}

func (srv *Server) runProcessCollector(ctx context.Context) {}

func (srv *Server) prepareRunEnvoyCommand(ctx context.Context, sharedArgs []string) (args []string) {
	if srv.cmd != nil && srv.cmd.Process != nil {
		log.Info(ctx).Msg("envoy: terminating previous envoy process")
		_ = srv.cmd.Process.Kill()
	}

	args = make([]string, len(sharedArgs))
	copy(args, sharedArgs)
	return args
}
