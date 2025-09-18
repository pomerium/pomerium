//go:build !linux

package envoy

import "os"

var shutdownSignal = os.Interrupt
