//go:build !linux && !darwin
// +build !linux,!darwin

package envoy

import (
	"context"

	"github.com/pomerium/pomerium/internal/log"
)

func (srv *Server) runProcessCollector(ctx context.Context) {}

func (srv *Server) prepareRunEnvoyCommand(ctx context.Context, sharedArgs []string) (exePath string, args []string) {
	if srv.cmd != nil && srv.cmd.Process != nil {
		log.Ctx(ctx).Info().Msg("envoy: terminating previous envoy process")
		_ = srv.cmd.Process.Kill()
	}

	args = make([]string, len(sharedArgs))
	copy(args, sharedArgs)

	return srv.envoyPath, args
}
