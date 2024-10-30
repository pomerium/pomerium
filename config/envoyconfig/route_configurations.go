package envoyconfig

import (
	"context"
	"fmt"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
)

const (
	mainRouteConfigurationName     = "main"
	mainQuicRouteConfigurationName = "main-quic"
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
		rc1, err := b.buildMainRouteConfiguration(ctx, cfg)
		if err != nil {
			return nil, err
		}
		routeConfigurations = append(routeConfigurations, rc1)

		if cfg.Options.CodecType == config.CodecTypeHTTP3 {
			// add a second, quic-specific route configuration, identical to main
			rc2 := proto.Clone(rc1).(*envoy_config_route_v3.RouteConfiguration)
			rc2.Name = mainQuicRouteConfigurationName
			routeConfigurations = append(routeConfigurations, rc2)

			// for the non-quic main route configuration, add an alt-svc to all routes indicating http/3 is available
			listenAddr := buildUDPAddress(cfg.Options.Addr, 443)
			listenPort := listenAddr.GetSocketAddress().GetPortValue()
			for _, vh := range rc1.VirtualHosts {
				vh.ResponseHeadersToAdd = append(vh.ResponseHeadersToAdd, &envoy_config_core_v3.HeaderValueOption{
					Header: &envoy_config_core_v3.HeaderValue{
						Key: "alt-svc",
						Value: fmt.Sprintf(`h3=":%d"; ma=86400, h3-29=":%d"; ma=86400`,
							listenPort, listenPort),
					},
					Append: &wrapperspb.BoolValue{Value: true},
				})
			}
		}
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
