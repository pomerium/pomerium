package envoyconfig

import (
	"context"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
)

const (
	mainRouteConfigurationName = "main"
)

// BuildRouteConfigurations builds the route configurations for the RDS service.
func (b *Builder) BuildRouteConfigurations(
	ctx context.Context,
	cfg *config.Config,
) ([]*envoy_config_route_v3.RouteConfiguration, error) {
	ctx, span := trace.StartSpan(ctx, "envoyconfig.Builder.BuildRouteConfigurations")
	defer span.End()

	var routeConfigurations []*envoy_config_route_v3.RouteConfiguration

	if config.IsAuthenticate(cfg.Options.Services) || config.IsProxy(cfg.Options.Services) {
		rc, err := b.buildMainRouteConfiguration(ctx, cfg)
		if err != nil {
			return nil, err
		}
		routeConfigurations = append(routeConfigurations, rc)
	}

	return routeConfigurations, nil
}

func (b *Builder) buildMainRouteConfiguration(
	_ context.Context,
	cfg *config.Config,
) (*envoy_config_route_v3.RouteConfiguration, error) {
	authorizeURLs, err := cfg.Options.GetInternalAuthorizeURLs()
	if err != nil {
		return nil, err
	}

	dataBrokerURLs, err := cfg.Options.GetInternalDataBrokerURLs()
	if err != nil {
		return nil, err
	}

	allHosts, err := getAllRouteableHosts(cfg.Options, cfg.Options.Addr)
	if err != nil {
		return nil, err
	}

	var virtualHosts []*envoy_config_route_v3.VirtualHost
	for _, host := range allHosts {
		vh, err := b.buildVirtualHost(cfg.Options, host, host)
		if err != nil {
			return nil, err
		}

		if cfg.Options.Addr == cfg.Options.GetGRPCAddr() {
			// if this is a gRPC service domain and we're supposed to handle that, add those routes
			if (config.IsAuthorize(cfg.Options.Services) && urlsMatchHost(authorizeURLs, host)) ||
				(config.IsDataBroker(cfg.Options.Services) && urlsMatchHost(dataBrokerURLs, host)) {
				rs, err := b.buildGRPCRoutes()
				if err != nil {
					return nil, err
				}
				vh.Routes = append(vh.Routes, rs...)
			}
		}

		// if we're the proxy, add all the policy routes
		if config.IsProxy(cfg.Options.Services) {
			rs, err := b.buildRoutesForPoliciesWithHost(cfg, host)
			if err != nil {
				return nil, err
			}
			vh.Routes = append(vh.Routes, rs...)
		}

		if len(vh.Routes) > 0 {
			virtualHosts = append(virtualHosts, vh)
		}
	}

	vh, err := b.buildVirtualHost(cfg.Options, "catch-all", "*")
	if err != nil {
		return nil, err
	}
	if config.IsProxy(cfg.Options.Services) {
		rs, err := b.buildRoutesForPoliciesWithCatchAll(cfg)
		if err != nil {
			return nil, err
		}
		vh.Routes = append(vh.Routes, rs...)
	}

	virtualHosts = append(virtualHosts, vh)

	rc, err := b.buildRouteConfiguration(mainRouteConfigurationName, virtualHosts)
	if err != nil {
		return nil, err
	}

	return rc, nil
}
