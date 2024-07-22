package envoyconfig

import (
	"context"
	"fmt"
	"strings"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
)

// BuildRouteConfigurations builds the route configurations for the RDS service.
func (b *Builder) BuildRouteConfigurations(
	ctx context.Context,
) ([]*envoy_config_route_v3.RouteConfiguration, error) {
	_, span := trace.StartSpan(ctx, "envoyconfig.Builder.BuildRouteConfigurations")
	defer span.End()

	var routeConfigurations []*envoy_config_route_v3.RouteConfiguration

	if config.IsAuthenticate(b.cfg.Options.Services) || config.IsProxy(b.cfg.Options.Services) {
		rc, err := b.buildMainRouteConfiguration()
		if err != nil {
			return nil, err
		}
		routeConfigurations = append(routeConfigurations, rc)
	}

	return routeConfigurations, nil
}

func (b *Builder) buildRouteConfiguration(name string, virtualHosts []*envoy_config_route_v3.VirtualHost) (*envoy_config_route_v3.RouteConfiguration, error) {
	return &envoy_config_route_v3.RouteConfiguration{
		Name:         name,
		VirtualHosts: virtualHosts,
		// disable cluster validation since the order of LDS/CDS updates isn't guaranteed
		ValidateClusters: &wrapperspb.BoolValue{Value: false},
	}, nil
}

func (b *Builder) buildMainRouteConfiguration() (*envoy_config_route_v3.RouteConfiguration, error) {
	authorizeURLs, err := b.cfg.Options.GetInternalAuthorizeURLs()
	if err != nil {
		return nil, err
	}

	dataBrokerURLs, err := b.cfg.Options.GetInternalDataBrokerURLs()
	if err != nil {
		return nil, err
	}

	hosts, policiesByHost, err := getAllRouteableHosts(b.cfg.Options, b.cfg.Options.Addr)
	if err != nil {
		return nil, err
	}

	virtualHosts := make([]*envoy_config_route_v3.VirtualHost, 0, hosts.Size())
	catchallVirtualHost, err := b.buildVirtualHost("catch-all", "*")
	if err != nil {
		return nil, err
	}
	seenCatchallPolicies := map[int]struct{}{}

	isProxy := config.IsProxy(b.cfg.Options.Services)
	isAuthorize := config.IsAuthorize(b.cfg.Options.Services)
	isDatabroker := config.IsDataBroker(b.cfg.Options.Services)
	isGRPCServiceDomain := b.cfg.Options.Addr == b.cfg.Options.GetGRPCAddr()

	for host := range hosts.Items() {
		if isProxy && strings.ContainsRune(host, '*') {
			// Group policies containing wildcards into a separate virtual host
			for _, policy := range policiesByHost[host] {
				if _, ok := seenCatchallPolicies[policy.Index]; ok {
					continue
				}
				seenCatchallPolicies[policy.Index] = struct{}{}
				policyRoutes, err := b.buildRoutesForPolicy(policy.Policy, fmt.Sprintf("policy-%d", policy.Index))
				if err != nil {
					return nil, err
				}
				catchallVirtualHost.Routes = append(catchallVirtualHost.Routes, policyRoutes...)
			}
			continue
		}

		vh, err := b.buildVirtualHost(host, host)
		if err != nil {
			return nil, err
		}

		if isGRPCServiceDomain {
			// if this is a gRPC service domain and we're supposed to handle that, add those routes
			if (isAuthorize && b.urlsMatchHost(authorizeURLs, host)) ||
				(isDatabroker && b.urlsMatchHost(dataBrokerURLs, host)) {
				rs, err := b.buildGRPCRoutes()
				if err != nil {
					return nil, err
				}
				vh.Routes = append(vh.Routes, rs...)
			}
		}

		// if we're the proxy, add all the policy routes
		if isProxy {
			for _, policy := range policiesByHost[host] {
				policyRoutes, err := b.buildRoutesForPolicy(policy.Policy, fmt.Sprintf("policy-%d", policy.Index))
				if err != nil {
					return nil, err
				}
				vh.Routes = append(vh.Routes, policyRoutes...)
			}
		}

		if len(vh.Routes) > 0 {
			virtualHosts = append(virtualHosts, vh)
		}
	}

	if len(catchallVirtualHost.Routes) > 0 {
		virtualHosts = append(virtualHosts, catchallVirtualHost)
	}

	rc, err := b.buildRouteConfiguration("main", virtualHosts)
	if err != nil {
		return nil, err
	}

	return rc, nil
}
