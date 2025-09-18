//go:build !linux

package controlplane

import (
	"context"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/health"
)

func (srv *Server) configureExtraProviders(
	ctx context.Context,
	cfg *config.Config,
	mgr health.ProviderManager,
	checks []health.Check,
) {
}
