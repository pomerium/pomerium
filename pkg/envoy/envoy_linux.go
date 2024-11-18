//go:build linux
// +build linux

package envoy

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"go.opencensus.io/stats/view"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
)

const baseIDName = "pomerium-envoy-base-id"

var restartEpoch struct {
	sync.Mutex
	value int
}

var sysProcAttr = &syscall.SysProcAttr{
	Setpgid:   true,
	Pdeathsig: syscall.SIGTERM,
}

func (srv *Server) runProcessCollector(ctx context.Context) {
	pc := metrics.NewProcessCollector("envoy")
	if err := view.Register(pc.Views()...); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("failed to register envoy process metric views")
	}
	defer view.Unregister(pc.Views()...)

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
				log.Ctx(ctx).Error().Err(err).Msg("failed to measure envoy process metrics")
			}
		}
	}
}

func (srv *Server) prepareRunEnvoyCommand(ctx context.Context, sharedArgs []string) (exePath string, args []string) {
	// release the previous process so we can hot-reload
	if srv.cmd != nil && srv.cmd.Process != nil {
		log.Ctx(ctx).Info().Msg("envoy: releasing envoy process for hot-reload")
		err := srv.cmd.Process.Release()
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Str("service", "envoy").Msg("envoy: failed to release envoy process for hot-reload")
		}
	}

	args = make([]string, len(sharedArgs))
	copy(args, sharedArgs)

	restartEpoch.Lock()
	if baseID, ok := readBaseID(); ok {
		args = append(args,
			"--base-id", strconv.Itoa(baseID),
			"--restart-epoch", strconv.Itoa(restartEpoch.value),
			"--drain-time-s", "60",
			"--parent-shutdown-time-s", "120",
			"--drain-strategy", "immediate",
		)
		restartEpoch.value++
	} else {
		args = append(args,
			"--use-dynamic-base-id",
			"--base-id-path", filepath.Join(os.TempDir(), baseIDName),
		)
		restartEpoch.value = 1
	}
	restartEpoch.Unlock()

	return srv.envoyPath, args
}

func readBaseID() (int, bool) {
	bs, err := os.ReadFile(filepath.Join(os.TempDir(), baseIDName))
	if err != nil {
		return 0, false
	}

	baseID, err := strconv.Atoi(string(bs))
	if err != nil {
		return 0, false
	}

	return baseID, true
}
