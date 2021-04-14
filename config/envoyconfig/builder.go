package envoyconfig

import (
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/httputil/reproxy"
)

// A Builder builds envoy config from pomerium config.
type Builder struct {
	localGRPCAddress string
	localHTTPAddress string
	filemgr          *filemgr.Manager
	reproxy          *reproxy.Handler
}

// New creates a new Builder.
func New(
	localGRPCAddress string,
	localHTTPAddress string,
	fileManager *filemgr.Manager,
	reproxyHandler *reproxy.Handler,
) *Builder {
	return &Builder{
		localGRPCAddress: localGRPCAddress,
		localHTTPAddress: localHTTPAddress,
		filemgr:          fileManager,
		reproxy:          reproxyHandler,
	}
}
