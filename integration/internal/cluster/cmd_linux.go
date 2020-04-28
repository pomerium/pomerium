// +build linux

package cluster

import (
	"context"
	"os/exec"
	"syscall"

	"github.com/onsi/gocleanup"
)

func commandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}
	gocleanup.Register(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	return cmd
}
