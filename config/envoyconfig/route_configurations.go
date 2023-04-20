package envoyconfig

import (
	"context"
	"crypto/tls"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// BuildRouteConfigurations builds the route configurations for the RDS service.
func (b *Builder) BuildRouteConfigurations(
	ctx context.Context,
	cfg *config.Config,
) ([]*envoy_config_route_v3.RouteConfiguration, error) {
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
	ctx context.Context,
	cfg *config.Config,
) (*envoy_config_route_v3.RouteConfiguration, error) {
	var certs []tls.Certificate
	if !cfg.Options.InsecureServer {
		var err error
		certs, err = getAllCertificates(cfg)
		if err != nil {
			return nil, err
		}
	}

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
		requireStrictTransportSecurity := cryptutil.HasCertificateForServerName(certs, host)
		vh, err := b.buildVirtualHost(cfg.Options, host, host, requireStrictTransportSecurity)
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
			rs, err := b.buildPolicyRoutes(cfg.Options, host, requireStrictTransportSecurity)
			if err != nil {
				return nil, err
			}
			vh.Routes = append(vh.Routes, rs...)
		}

		if len(vh.Routes) > 0 {
			virtualHosts = append(virtualHosts, vh)
		}
	}

	vh, err := b.buildVirtualHost(cfg.Options, "catch-all", "*", false)
	if err != nil {
		return nil, err
	}
	virtualHosts = append(virtualHosts, vh)

	rc, err := b.buildRouteConfiguration("main", virtualHosts)
	if err != nil {
		return nil, err
	}

	return rc, nil
}
