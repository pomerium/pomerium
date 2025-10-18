package envoyconfig

import (
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/httputil/reproxy"
)

// A Builder builds envoy config from pomerium config.
type Builder struct {
	localGRPCAddress      string
	localHTTPAddress      string
	localDebugAddress     string
	localMetricsAddress   string
	filemgr               *filemgr.Manager
	reproxy               *reproxy.Handler
	addIPV6InternalRanges bool
}

// New creates a new Builder.
func New(
	localGRPCAddress string,
	localHTTPAddress string,
	localDebugAddress string,
	localMetricsAddress string,
	fileManager *filemgr.Manager,
	reproxyHandler *reproxy.Handler,
	addIPV6InternalRanges bool,
) *Builder {
	if reproxyHandler == nil {
		reproxyHandler = reproxy.New()
	}
	return &Builder{
		localGRPCAddress:      localGRPCAddress,
		localHTTPAddress:      localHTTPAddress,
		localDebugAddress:     localDebugAddress,
		localMetricsAddress:   localMetricsAddress,
		filemgr:               fileManager,
		reproxy:               reproxyHandler,
		addIPV6InternalRanges: addIPV6InternalRanges,
	}
}
