package envoyconfig

import (
	"context"

	envoy_generic_proxy_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/generic_proxy/v3"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

// BuildSSHRouteConfigurations builds the route configurations for the generic_proxy
// SSH RDS service. Returning these as a separate xDS resource (rather than inlining
// them into the SSH listener) is what allows route changes to propagate without
// modifying the listener and triggering a drain.
//
// The returned slice always contains zero or one entries: a single
// "ssh-route-config" resource keyed by SSHRouteConfigName when the SSH listener is
// active, or nil otherwise.
func (b *Builder) BuildSSHRouteConfigurations(
	ctx context.Context,
	cfg *config.Config,
) ([]*envoy_generic_proxy_v3.RouteConfiguration, error) {
	_, span := trace.Continue(ctx, "envoyconfig.Builder.BuildSSHRouteConfigurations")
	defer span.End()

	if !shouldStartSSHListener(cfg.Options) || cfg.Options.SSHAddr == "" {
		return nil, nil
	}

	rc, err := buildRouteConfig(cfg)
	if err != nil {
		return nil, err
	}
	rc.Name = SSHRouteConfigName
	return []*envoy_generic_proxy_v3.RouteConfiguration{rc}, nil
}
