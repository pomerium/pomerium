//go:build linux

package recording

import "golang.org/x/sys/unix"

const FIONREAD = unix.TIOCINQ
