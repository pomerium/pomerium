// +build !linux

package cluster

import (
	"context"
	"os/exec"

	"github.com/onsi/gocleanup"
)

func commandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	gocleanup.Register(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	return cmd
}
