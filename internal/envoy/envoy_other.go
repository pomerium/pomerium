// +build !linux,!darwin

package envoy

import (
	"context"
	"os/exec"

	"github.com/pomerium/pomerium/internal/log"
)

// Command creates an exec.Cmd using the embedded envoy binary.
func Command(ctx context.Context, arg ...string) (*exec.Cmd, error) {
	fullEnvoyPath, err := setup()
	if err != nil {
		return nil, err
	}

	return exec.CommandContext(ctx, fullEnvoyPath, arg...), nil
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
