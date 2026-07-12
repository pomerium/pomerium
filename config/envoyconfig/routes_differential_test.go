package envoyconfig

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/httputil/reproxy"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// buildRoutesForPoliciesWithHostByScan preserves the linear-scan behavior
// replaced by policyHostIndex.
func buildRoutesForPoliciesWithHostByScan(t *testing.T, b *Builder, cfg *config.Config, host string) []*envoy_config_route_v3.Route {
	t.Helper()
	var routes []*envoy_config_route_v3.Route
	for i, policy := range cfg.Options.GetAllPoliciesIndexed() {
		fromURL, err := urlutil.ParseAndValidateURL(policy.From)
		require.NoError(t, err)
		if !urlMatchesHost(fromURL, host) {
			continue
		}
		pr, err := b.buildRoutesForPolicy(cfg, policy, fromURL, fmt.Sprintf("policy-%d", i))
		require.NoError(t, err)
		routes = append(routes, pr...)
	}
	return routes
}

// buildRoutesForPoliciesWithCatchAllByScan preserves the catch-all scan
// replaced by policyHostIndex.
func buildRoutesForPoliciesWithCatchAllByScan(t *testing.T, b *Builder, cfg *config.Config) []*envoy_config_route_v3.Route {
	t.Helper()
	var routes []*envoy_config_route_v3.Route
	for i, policy := range cfg.Options.GetAllPoliciesIndexed() {
		fromURL, err := urlutil.ParseAndValidateURL(policy.From)
		require.NoError(t, err)
		if !strings.Contains(fromURL.Host, "*") {
			continue
		}
		pr, err := b.buildRoutesForPolicy(cfg, policy, fromURL, fmt.Sprintf("policy-%d", i))
		require.NoError(t, err)
		routes = append(routes, pr...)
	}
	return routes
}

func assertRoutesEqualInOrder(t *testing.T, label string, want, got []*envoy_config_route_v3.Route) {
	t.Helper()
	require.Equal(t, len(want), len(got), "%s: route count differs (old=%d new=%d)", label, len(want), len(got))
	for i := range want {
		if !proto.Equal(want[i], got[i]) {
			t.Errorf("%s: route[%d] differs old-vs-new\n old cluster=%s match=%v\n new cluster=%s match=%v",
				label, i,
				want[i].GetRoute().GetCluster(), want[i].GetMatch(),
				got[i].GetRoute().GetCluster(), got[i].GetMatch())
		}
	}
}

func hostIndexTestOptions(t *testing.T) config.Options {
	t.Helper()
	// Policies deliberately interleave: same host different paths, exact + wildcard
	// for the same apex, explicit default and non-default ports, and duplicates,
	// then split across the three GetAllPolicies slices to exercise iteration order.
	return config.Options{
		CookieName:             "pomerium",
		DefaultUpstreamTimeout: 3 * time.Second,
		SharedKey:              cryptutil.NewBase64Key(),
		Services:               "proxy",
		Policies: []config.Policy{
			{From: "https://foo.example.com", Path: "/a", To: mustParseWeightedURLs(t, "https://to1.example.com")},
			{From: "https://*.example.com", To: mustParseWeightedURLs(t, "https://wild.example.com")},
			{From: "https://foo.example.com", Path: "/b", To: mustParseWeightedURLs(t, "https://to2.example.com")},
		},
		Routes: []config.Policy{
			{From: "https://foo.example.com:8443", To: mustParseWeightedURLs(t, "https://to3.example.com")},
			{From: "https://foo.example.com:443", Path: "/c", To: mustParseWeightedURLs(t, "https://to4.example.com")},
			{From: "https://bar.example.com", To: mustParseWeightedURLs(t, "https://to5.example.com")},
			{
				From: "tcp+https://proxy.example.com/db.example.com:5432/cache.example.com:6379",
				To:   mustParseWeightedURLs(t, "tcp://upstream.example.com:5432"),
			},
		},
		AdditionalPolicies: []config.Policy{
			{From: "https://foo.example.com", Path: "/d", To: mustParseWeightedURLs(t, "https://to6.example.com")},
			{From: "https://*.other.example.com", To: mustParseWeightedURLs(t, "https://wild2.example.com")},
			{From: "https://example.com", To: mustParseWeightedURLs(t, "https://apex.example.com")},
		},
	}
}

// hostIndexCandidateHosts collects every host string that any policy could
// conceivably be bucketed under, under either value of includeDefaultPort, so
// the diff can't miss a host where old and new might disagree.
func hostIndexCandidateHosts(t *testing.T, opts *config.Options) []string {
	t.Helper()
	seen := map[string]bool{}
	var hosts []string
	add := func(h string) {
		if h == "" || strings.Contains(h, "*") || seen[h] {
			return
		}
		seen[h] = true
		hosts = append(hosts, h)
	}
	for p := range opts.GetAllPolicies() {
		u, err := urlutil.ParseAndValidateURL(p.From)
		require.NoError(t, err)
		for _, d := range urlutil.GetDomainsForURL(u, true) {
			add(d)
		}
		for _, d := range urlutil.GetDomainsForURL(u, false) {
			add(d)
		}
		// concrete hosts a wildcard could expand to
		add(strings.Replace(u.Hostname(), "*", "sub", 1))
	}
	slices.Sort(hosts)
	return hosts
}

func TestPolicyHostIndexMatchesScan(t *testing.T) {
	for _, matchAnyPort := range []bool{false, true} {
		t.Run(fmt.Sprintf("matchAnyIncomingPort=%v", matchAnyPort), func(t *testing.T) {
			opts := hostIndexTestOptions(t)
			if matchAnyPort {
				opts.RuntimeFlags = map[config.RuntimeFlag]bool{config.RuntimeFlagMatchAnyIncomingPort: true}
			}
			cfg := config.New(&opts)

			b := &Builder{filemgr: filemgr.NewManager(), reproxy: reproxy.New()}

			// New indexed path (production).
			idx, err := indexPoliciesByHost(cfg.Options)
			require.NoError(t, err)

			hosts := hostIndexCandidateHosts(t, cfg.Options)
			require.NotEmpty(t, hosts)
			t.Logf("candidate hosts: %v", hosts)

			for _, host := range hosts {
				old := buildRoutesForPoliciesWithHostByScan(t, b, cfg, host)
				got, err := b.buildRoutesForPoliciesWithHost(cfg, idx, host)
				require.NoError(t, err)
				assertRoutesEqualInOrder(t, "host="+host, old, got)
			}

			// Catch-all virtual host.
			oldCatch := buildRoutesForPoliciesWithCatchAllByScan(t, b, cfg)
			gotCatch, err := b.buildRoutesForPoliciesWithCatchAll(cfg, idx)
			require.NoError(t, err)
			assertRoutesEqualInOrder(t, "catch-all", oldCatch, gotCatch)
		})
	}
}
