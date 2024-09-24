package log

import "sync/atomic"

var (
	// Debug option to disable the Zap log shim
	DebugDisableZapLogger atomic.Bool
	// Debug option to suppress global warnings
	DebugDisableGlobalWarnings atomic.Bool
)
