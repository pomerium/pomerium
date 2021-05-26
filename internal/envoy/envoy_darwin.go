// +build darwin

package envoy

import (
	"context"
	"syscall"
)

var sysProcAttr = &syscall.SysProcAttr{
	Setpgid: true,
}

func (srv *Server) runProcessCollector(ctx context.Context) {}
