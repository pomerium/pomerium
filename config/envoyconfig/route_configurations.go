package envoyconfig

import (
	"context"
	"fmt"
	"strings"

	rttrace "runtime/trace"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
)

// BuildRouteConfigurations builds the route configurations for the RDS service.
func (b *ScopedBuilder) BuildRouteConfiguration(
	ctx context.Context,
) (*envoy_config_route_v3.RouteConfiguration, error) {
	ctx, span := trace.StartSpan(ctx, "envoyconfig.Builder.BuildRouteConfigurations")
	defer span.End()
	ctx, task := rttrace.NewTask(ctx, "envoyconfig.Builder.BuildRouteConfigurations")
	defer task.End()
	defer rttrace.StartRegion(ctx, "BuildRouteConfigurations").End()

	if config.IsAuthenticate(b.cfg.Options.Services) || config.IsProxy(b.cfg.Options.Services) {
		return b.buildMainRouteConfiguration(ctx)
	}

	return nil, fmt.Errorf("unsupported service type: %s", b.cfg.Options.Services)
}

func (b *ScopedBuilder) buildRouteConfiguration(name string, virtualHosts []*envoy_config_route_v3.VirtualHost) (*envoy_config_route_v3.RouteConfiguration, error) {
	return &envoy_config_route_v3.RouteConfiguration{
		Name:         name,
		VirtualHosts: virtualHosts,
		// disable cluster validation since the order of LDS/CDS updates isn't guaranteed
		ValidateClusters: &wrapperspb.BoolValue{Value: false},
	}, nil
}

func (b *ScopedBuilder) buildMainRouteConfiguration(ctx context.Context) (*envoy_config_route_v3.RouteConfiguration, error) {
	authorizeURLs, err := b.cfg.Options.GetInternalAuthorizeURLs()
	if err != nil {
		return nil, err
	}

	dataBrokerURLs, err := b.cfg.Options.GetInternalDataBrokerURLs()
	if err != nil {
		return nil, err
	}

	allHosts, policiesByHost, err := getAllRouteableHosts(b.cfg.Options, b.cfg.Options.Addr)
	if err != nil {
		return nil, err
	}

	var virtualHosts []*envoy_config_route_v3.VirtualHost
	rttrace.Log(ctx, "", "start: building virtual hosts")
	catchallVirtualHost, err := b.buildVirtualHost(ctx, "catch-all", "*")
	if err != nil {
		return nil, err
	}
	seenCatchallPolicies := map[int]struct{}{}
	isProxy := config.IsProxy(b.cfg.Options.Services)
	for _, host := range allHosts {
		if isProxy && strings.Contains(host, "*") {
			for _, policy := range policiesByHost[host] {
				if _, ok := seenCatchallPolicies[policy.Index]; ok {
					continue
				}
				seenCatchallPolicies[policy.Index] = struct{}{}
				policyRoutes, err := b.buildRoutesForPolicy(ctx, policy.Policy, fmt.Sprintf("policy-%d", policy.Index))
				if err != nil {
					return nil, err
				}
				catchallVirtualHost.Routes = append(catchallVirtualHost.Routes, policyRoutes...)
			}
			continue
		}

		vh, err := b.buildVirtualHost(ctx, host, host)
		if err != nil {
			return nil, err
		}

		if b.cfg.Options.Addr == b.cfg.Options.GetGRPCAddr() {
			// if this is a gRPC service domain and we're supposed to handle that, add those routes
			if (config.IsAuthorize(b.cfg.Options.Services) && b.urlsMatchHost(authorizeURLs, host)) ||
				(config.IsDataBroker(b.cfg.Options.Services) && b.urlsMatchHost(dataBrokerURLs, host)) {
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
				policyRoutes, err := b.buildRoutesForPolicy(ctx, policy.Policy, fmt.Sprintf("policy-%d", policy.Index))
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
	rttrace.Log(ctx, "", "end: building virtual hosts")

	rttrace.Log(ctx, "", "start: building route configuration")
	rc, err := b.buildRouteConfiguration("main", virtualHosts)
	if err != nil {
		return nil, err
	}
	rttrace.Log(ctx, "", "end: building route configuration")

	return rc, nil
}
