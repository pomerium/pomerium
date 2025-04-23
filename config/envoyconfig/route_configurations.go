package envoyconfig

import (
	"cmp"
	"context"
	"net/url"
	"strings"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/hashicorp/go-set/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

// BuildRouteConfigurations builds the route configurations for the RDS service.
func (b *Builder) BuildRouteConfigurations(
	ctx context.Context,
	cfg *config.Config,
) ([]*envoy_config_route_v3.RouteConfiguration, error) {
	ctx, span := trace.Continue(ctx, "envoyconfig.Builder.BuildRouteConfigurations")
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

	allHosts, mcpHosts, err := getAllRouteableHosts(cfg.Options, cfg.Options.Addr)
	if err != nil {
		return nil, err
	}

	var virtualHosts []*envoy_config_route_v3.VirtualHost
	for _, host := range allHosts {
		vh, err := b.buildVirtualHost(cfg.Options, host, host, mcpHosts[host])
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

	vh, err := b.buildVirtualHost(cfg.Options, "catch-all", "*", false)
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

	rc := newRouteConfiguration("main", virtualHosts)
	return rc, nil
}

func getAllRouteableHosts(options *config.Options, addr string) ([]string, map[string]bool, error) {
	allHosts := set.NewTreeSet(cmp.Compare[string])
	mcpHosts := make(map[string]bool)

	if addr == options.Addr {
		hosts, hostsMCP, err := options.GetAllRouteableHTTPHosts()
		if err != nil {
			return nil, nil, err
		}
		allHosts.InsertSlice(hosts)
		// Merge any MCP hosts
		for host, isMCP := range hostsMCP {
			if isMCP {
				mcpHosts[host] = true
			}
		}
	}

	if addr == options.GetGRPCAddr() {
		hosts, err := options.GetAllRouteableGRPCHosts()
		if err != nil {
			return nil, nil, err
		}
		allHosts.InsertSlice(hosts)
	}

	var filtered []string
	for host := range allHosts.Items() {
		if !strings.Contains(host, "*") {
			filtered = append(filtered, host)
		}
	}
	return filtered, mcpHosts, nil
}

func newRouteConfiguration(name string, virtualHosts []*envoy_config_route_v3.VirtualHost) *envoy_config_route_v3.RouteConfiguration {
	return &envoy_config_route_v3.RouteConfiguration{
		Name:         name,
		VirtualHosts: virtualHosts,
		// disable cluster validation since the order of LDS/CDS updates isn't guaranteed
		ValidateClusters: &wrapperspb.BoolValue{Value: false},
	}
}

func urlsMatchHost(urls []*url.URL, host string) bool {
	for _, u := range urls {
		if urlMatchesHost(u, host) {
			return true
		}
	}
	return false
}

func urlMatchesHost(u *url.URL, host string) bool {
	for _, h := range urlutil.GetDomainsForURL(u, true) {
		if h == host {
			return true
		}
	}
	return false
}
