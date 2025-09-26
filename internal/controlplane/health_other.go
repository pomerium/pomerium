//go:build !linux

package controlplane

import (
	"context"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/health"
)

func (srv *Server) configureExtraProviders(
	_ context.Context,
	_ *config.Config,
	_ health.ProviderManager,
	_ []health.Check,
) {
}
