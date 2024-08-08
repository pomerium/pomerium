package config

import (
	"runtime/debug"
	"sync"

	"github.com/valyala/bytebufferpool"
)

func DebugResetPools() {
	checksumBufferPool = bytebufferpool.Pool{}
	policyPool = sync.Pool{New: policyPool.New}
	debug.FreeOSMemory()
}
