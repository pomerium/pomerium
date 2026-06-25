package envoyconfig

import (
	"cmp"
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"

	xds_core_v3 "github.com/cncf/xds/go/xds/core/v3"
	xds_matcher_v3 "github.com/cncf/xds/go/xds/type/matcher/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_generic_proxy_action_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/generic_proxy/action/v3"
	envoy_generic_proxy_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/generic_proxy/matcher/v3"
	envoy_generic_proxy_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/generic_proxy/v3"
	"github.com/hashicorp/go-set/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

type RouteConfiguration struct {
	Name   string
	Config proto.Message
}

// BuildRouteConfigurations builds the route configurations for the RDS service.
func (b *Builder) BuildRouteConfigurations(
	ctx context.Context,
	cfg *config.Config,
) ([]RouteConfiguration, error) {
	if !config.IsAuthenticate(cfg.Options.Services) && !config.IsProxy(cfg.Options.Services) {
		return nil, nil
	}

	ctx, span := trace.Continue(ctx, "envoyconfig.Builder.BuildRouteConfigurations")
	defer span.End()

	var routeConfigurations []RouteConfiguration
	{
		rc, err := b.buildMainRouteConfiguration(ctx, cfg)
		if err != nil {
			return nil, err
		}
		routeConfigurations = append(routeConfigurations, RouteConfiguration{
			Name:   "main",
			Config: rc,
		})
	}
	{
		rc, err := buildSSHRouteConfiguration(cfg)
		if err != nil {
			return nil, err
		}
		routeConfigurations = append(routeConfigurations, RouteConfiguration{
			Name:   "ssh",
			Config: rc,
		})
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

func buildSSHRouteConfiguration(cfg *config.Config) (*envoy_generic_proxy_v3.RouteConfiguration, error) {
	var matchers []*xds_matcher_v3.Matcher_MatcherList_FieldMatcher
	for policy := range cfg.Options.GetAllPolicies() {
		if !policy.IsSSH() {
			continue
		}
		fromURL, err := urlutil.ParseAndValidateURL(policy.From)
		if err != nil {
			return nil, err
		}
		fromHost := fromURL.Hostname()
		if len(policy.To) > 1 {
			return nil, fmt.Errorf("only one 'to' entry allowed for ssh routes")
		}
		to := policy.To[0].URL
		if to.Scheme != "ssh" {
			return nil, fmt.Errorf("'to' route url must have ssh scheme")
		}
		matchers = append(matchers, &xds_matcher_v3.Matcher_MatcherList_FieldMatcher{
			Predicate: &xds_matcher_v3.Matcher_MatcherList_Predicate{
				MatchType: &xds_matcher_v3.Matcher_MatcherList_Predicate_SinglePredicate_{
					SinglePredicate: &xds_matcher_v3.Matcher_MatcherList_Predicate_SinglePredicate{
						Input: &xds_core_v3.TypedExtensionConfig{
							Name:        "host",
							TypedConfig: marshalAny(&envoy_generic_proxy_matcher_v3.HostMatchInput{}),
						},
						Matcher: &xds_matcher_v3.Matcher_MatcherList_Predicate_SinglePredicate_ValueMatch{
							ValueMatch: &xds_matcher_v3.StringMatcher{
								MatchPattern: &xds_matcher_v3.StringMatcher_Exact{
									Exact: fromHost,
								},
							},
						},
					},
				},
			},
			OnMatch: &xds_matcher_v3.Matcher_OnMatch{
				OnMatch: &xds_matcher_v3.Matcher_OnMatch_Action{
					Action: &xds_core_v3.TypedExtensionConfig{
						Name: "route",
						TypedConfig: marshalAny(&envoy_generic_proxy_action_v3.RouteAction{
							Name: policy.ID,
							ClusterSpecifier: &envoy_generic_proxy_action_v3.RouteAction_Cluster{
								Cluster: GetClusterID(policy),
							},
							Timeout: durationpb.New(0),
						}),
					},
				},
			},
		})
	}

	// Note that this is a separate xds resource type than the standard route
	// configuration type used for http routes.
	return &envoy_generic_proxy_v3.RouteConfiguration{
		Name: "ssh", // matches the generic rds route_config_name
		Routes: &xds_matcher_v3.Matcher{
			MatcherType: &xds_matcher_v3.Matcher_MatcherList_{
				MatcherList: &xds_matcher_v3.Matcher_MatcherList{
					Matchers: matchers,
				},
			},
		},
	}, nil
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
	return slices.Contains(urlutil.GetDomainsForURL(u, true), host)
}
