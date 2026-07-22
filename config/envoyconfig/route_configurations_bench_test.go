package envoyconfig

import (
	"fmt"
	"testing"
	"time"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// benchOptions builds Options with n policies, each matching a distinct
// single host in From. Distinct hosts force BuildRouteConfigurations to
// evaluate every policy against every host, which is the O(hosts * policies)
// path this benchmark targets.
func benchOptions(b *testing.B, n int) *config.Options {
	b.Helper()

	policies := make([]config.Policy, n)
	for i := range n {
		to, err := config.ParseWeightedUrls(fmt.Sprintf("https://up%d.example.com", i))
		if err != nil {
			b.Fatalf("parse to url: %v", err)
		}
		policies[i] = config.Policy{
			From: fmt.Sprintf("https://r%d.example.com", i),
			To:   to,
		}
		if err := policies[i].Validate(); err != nil {
			b.Fatalf("policy %d failed validation: %v", i, err)
		}
	}

	return &config.Options{
		CookieName:             "pomerium",
		DefaultUpstreamTimeout: 3 * time.Second,
		SharedKey:              cryptutil.NewBase64Key(),
		Services:               "proxy",
		Policies:               policies,
	}
}

func BenchmarkBuildRouteConfigurations(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("policies=%d", n), func(b *testing.B) {
			if n == 10000 && testing.Short() {
				b.Skip("policies=10000 takes ~45s/op; run without -short for the full scaling curve")
			}
			options := benchOptions(b, n)
			cfg := config.New(options)
			bd := New("connect", "grpc", "http", "debug", "metrics", filemgr.NewManager(), nil, true)
			ctx := b.Context()

			routeConfigurations, err := bd.BuildRouteConfigurations(ctx, cfg)
			if err != nil {
				b.Fatalf("BuildRouteConfigurations: %v", err)
			}
			if got := countRoutes(b, routeConfigurations); got < n {
				b.Fatalf("sanity check failed: built %d routes, want at least %d", got, n)
			}

			b.ReportAllocs()
			for b.Loop() {
				if _, err := bd.BuildRouteConfigurations(ctx, cfg); err != nil {
					b.Fatalf("BuildRouteConfigurations: %v", err)
				}
			}
		})
	}
}

func BenchmarkGetAllRouteableHTTPHosts(b *testing.B) {
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("policies=%d", n), func(b *testing.B) {
			options := benchOptions(b, n)

			hosts, _, err := options.GetAllRouteableHTTPHosts()
			if err != nil {
				b.Fatalf("GetAllRouteableHTTPHosts: %v", err)
			}
			if len(hosts) < n {
				b.Fatalf("sanity check failed: got %d hosts, want at least %d", len(hosts), n)
			}

			b.ReportAllocs()
			for b.Loop() {
				if _, _, err := options.GetAllRouteableHTTPHosts(); err != nil {
					b.Fatalf("GetAllRouteableHTTPHosts: %v", err)
				}
			}
		})
	}
}

// countRoutes returns the total number of routes across all virtual hosts of
// the "main" route configuration, which is where policy routes land.
func countRoutes(b *testing.B, routeConfigurations []RouteConfiguration) int {
	b.Helper()

	count := 0
	for _, rc := range routeConfigurations {
		main, ok := rc.Config.(*envoy_config_route_v3.RouteConfiguration)
		if !ok {
			continue
		}
		for _, vh := range main.GetVirtualHosts() {
			count += len(vh.GetRoutes())
		}
	}
	return count
}
