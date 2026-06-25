//go:build linux

package ipc

import "golang.org/x/sys/unix"

const FIONREAD = unix.TIOCINQ
