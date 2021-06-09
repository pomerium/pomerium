// +build linux

package envoy

import (
	"context"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"go.opencensus.io/stats/view"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
)

const baseIDPath = "/tmp/pomerium-envoy-base-id"

var restartEpoch struct {
	sync.Mutex
	value int
}

var sysProcAttr = &syscall.SysProcAttr{
	Setpgid:   true,
	Pdeathsig: syscall.SIGTERM,
}

// Command creates an exec.Cmd using the embedded envoy binary.
func Command(ctx context.Context, arg ...string) (*exec.Cmd, error) {
	fullEnvoyPath, err := setup()
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, fullEnvoyPath, arg...)
	cmd.Dir = filepath.Dir(fullEnvoyPath)
	return cmd, nil
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

func (srv *Server) prepareRunEnvoyCommand(ctx context.Context, sharedArgs []string) (args []string) {
	// release the previous process so we can hot-reload
	if srv.cmd != nil && srv.cmd.Process != nil {
		log.Info(ctx).Msg("envoy: releasing envoy process for hot-reload")
		err := srv.cmd.Process.Release()
		if err != nil {
			log.Warn(ctx).Err(err).Str("service", "envoy").Msg("envoy: failed to release envoy process for hot-reload")
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
			"--base-id-path", baseIDPath,
		)
		restartEpoch.value = 1
	}
	restartEpoch.Unlock()

	return args
}

func readBaseID() (int, bool) {
	bs, err := ioutil.ReadFile(baseIDPath)
	if err != nil {
		return 0, false
	}

	baseID, err := strconv.Atoi(string(bs))
	if err != nil {
		return 0, false
	}

	return baseID, true
}
