//go:build linux

package envoy

import "syscall"

var shutdownSignal = syscall.SIGTERM
