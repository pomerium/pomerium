// +build !linux,!darwin

package envoy

import (
	"context"
)

func (srv *Server) runProcessCollector(ctx context.Context) {}
