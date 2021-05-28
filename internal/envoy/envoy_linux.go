// +build linux

package envoy

import (
	"context"
	"syscall"
	"time"

	"go.opencensus.io/stats/view"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
)

var sysProcAttr = &syscall.SysProcAttr{
	Setpgid:   true,
	Pdeathsig: syscall.SIGTERM,
}

func (srv *Server) runProcessCollector(ctx context.Context) {
	pc := metrics.NewProcessCollector("envoy")
	if err := view.Register(pc.Views()...); err != nil {
		log.Error(ctx).Err(err).Msg("failed to register envoy process metric views")
	}

	const collectInterval = time.Second * 10
	ticker := time.NewTicker(collectInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		var pid int
		srv.mu.Lock()
		if srv.cmd != nil && srv.cmd.Process != nil {
			pid = srv.cmd.Process.Pid
		}
		srv.mu.Unlock()

		if pid > 0 {
			err := pc.Measure(ctx, pid)
			if err != nil {
				log.Error(ctx).Err(err).Msg("failed to measure envoy process metrics")
			}
		}
	}
}
