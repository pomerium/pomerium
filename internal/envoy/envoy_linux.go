// +build linux

package envoy

import "syscall"

var sysProcAttr = &syscall.SysProcAttr{
	Pdeathsig: syscall.SIGTERM,
}
