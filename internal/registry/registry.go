// Package registry implements a service registry server.
package registry

import (
	"io"

	registrypb "github.com/pomerium/pomerium/pkg/grpc/registry"
)

// Interface is a registry implementation.
type Interface interface {
	registrypb.RegistryServer
	io.Closer
}
