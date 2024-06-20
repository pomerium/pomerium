package config_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func BenchmarkGetIdentityProviderForRequestURL_Old(b *testing.B) {
	runBench := func(numPolicies int) func(b *testing.B) {
		return func(b *testing.B) {
			b.ReportAllocs()
			options := config.NewDefaultOptions()
			sharedKey := cryptutil.NewKey()
			options.SharedKey = base64.StdEncoding.EncodeToString(sharedKey)
			options.InsecureServer = true
			options.Provider = "oidc"
			options.ProviderURL = "https://oidc.example.com"
			options.ClientID = "client_id"
			options.ClientSecret = "client_secret"
			urlFormat := "https://*.foo.bar.test-%d.example.com"
			for i := range numPolicies {
				options.Policies = append(options.Policies,
					config.Policy{
						From:            fmt.Sprintf(urlFormat, i),
						To:              mustParseWeightedURLs(b, fmt.Sprintf("https://p2-%d", i)),
						IDPClientID:     fmt.Sprintf("client_id_%d", i),
						IDPClientSecret: fmt.Sprintf("client_secret_%d", i),
					},
				)
			}
			require.NoError(b, options.Validate())

			b.ResetTimer()
			for range b.N {
				idp, err := options.GetIdentityProviderForRequestURL(fmt.Sprintf(urlFormat, numPolicies-1))
				require.NoError(b, err)
				require.Equal(b, fmt.Sprintf("client_id_%d", numPolicies-1), idp.ClientId)
				require.Equal(b, fmt.Sprintf("client_secret_%d", numPolicies-1), idp.ClientSecret)
			}
		}
	}

	b.Run("5 policies", runBench(5))
	b.Run("50 policies", runBench(50))
	b.Run("500 policies", runBench(500))
	b.Run("5000 policies", runBench(5000))
}

var bench = func(fill func(i int, p *config.Policy) string, numPolicies int) func(b *testing.B) {
	return func(b *testing.B) {
		b.ReportAllocs()
		options := config.NewDefaultOptions()
		sharedKey := cryptutil.NewKey()
		options.SharedKey = base64.StdEncoding.EncodeToString(sharedKey)
		options.InsecureServer = true
		options.Provider = "oidc"
		options.ProviderURL = "https://oidc.example.com"
		options.ClientID = "client_id"
		options.ClientSecret = "client_secret"
		var allUrls []string
		for i := range numPolicies {
			p := config.Policy{
				To:              mustParseWeightedURLs(b, fmt.Sprintf("https://p2-%d", i)),
				IDPClientID:     fmt.Sprintf("client_id_%d", i),
				IDPClientSecret: fmt.Sprintf("client_secret_%d", i),
			}

			allUrls = append(allUrls, fill(i, &p))
			options.Policies = append(options.Policies, p)
		}
		require.NoError(b, options.Validate())

		cache, err := config.NewPolicyCache(options)
		require.NoError(b, err)

		b.ResetTimer()
		for i := range b.N {
			// replace all *s in the url with a number, which is valid for both
			// hostname segments and ports.
			reqURL := strings.ReplaceAll(allUrls[i%numPolicies], "*", fmt.Sprint(i))
			idp, err := cache.GetIdentityProviderForRequestURL(options, reqURL)
			require.NoError(b, err)
			require.Equal(b, fmt.Sprintf("client_id_%d", i%numPolicies), idp.ClientId)
			require.Equal(b, fmt.Sprintf("client_secret_%d", i%numPolicies), idp.ClientSecret)
		}
	}
}

func BenchmarkGetIdentityProviderForRequestURL_New_DomainMatchOnly(b *testing.B) {
	domainMatchingOnly := func(i int, p *config.Policy) string {
		p.From = fmt.Sprintf("https://*.foo.bar.test-%d.example.com", i)
		return p.From
	}

	b.Run("5 policies (domain matching only)", bench(domainMatchingOnly, 5))
	b.Run("50 policies (domain matching only)", bench(domainMatchingOnly, 50))
	b.Run("500 policies (domain matching only)", bench(domainMatchingOnly, 500))
	b.Run("5000 policies (domain matching only)", bench(domainMatchingOnly, 5000))
}

func BenchmarkGetIdentityProviderForRequestURL_New_DomainPortMatchOnly(b *testing.B) {
	domainPortMatchingOnly := func(i int, p *config.Policy) string {
		p.From = fmt.Sprintf("https://*.foo.bar.test-%d.example.com", i)
		if i%5 == 0 {
			p.From += ":9999"
		} else if i%2 == 0 {
			p.From += ":443"
		}
		return p.From
	}

	b.Run("5 policies (domain+port matching only)", bench(domainPortMatchingOnly, 5))
	b.Run("50 policies (domain+port matching only)", bench(domainPortMatchingOnly, 50))
	b.Run("500 policies (domain+port matching only)", bench(domainPortMatchingOnly, 500))
	b.Run("5000 policies (domain+port matching only)", bench(domainPortMatchingOnly, 5000))
}

func BenchmarkGetIdentityProviderForRequestURL_New_PathMatchOnly(b *testing.B) {
	pathMatchingOnly := func(i int, p *config.Policy) string {
		p.From = "https://example.com"
		p.Path = fmt.Sprintf("/foo/bar/path%d", i)
		return p.From + p.Path
	}
	b.Run("5 policies (path matching only)", bench(pathMatchingOnly, 5))
	b.Run("50 policies (path matching only)", bench(pathMatchingOnly, 50))
	b.Run("500 policies (path matching only)", bench(pathMatchingOnly, 500))
	b.Run("5000 policies (path matching only)", bench(pathMatchingOnly, 5000))
}

func BenchmarkGetIdentityProviderForRequestURL_New_PrefixMatchOnly(b *testing.B) {
	prefixMatchingOnly := func(i int, p *config.Policy) string {
		p.From = "https://example.com"
		p.Prefix = fmt.Sprintf("/foo/bar/%d/", i)
		return p.From + p.Prefix + "/subpath"
	}
	b.Run("5 policies (prefix matching only)", bench(prefixMatchingOnly, 5))
	b.Run("50 policies (prefix matching only)", bench(prefixMatchingOnly, 50))
	b.Run("500 policies (prefix matching only)", bench(prefixMatchingOnly, 500))
	b.Run("5000 policies (prefix matching only)", bench(prefixMatchingOnly, 5000))
}

func BenchmarkGetIdentityProviderForRequestURL_New_DomainAndPathMatching(b *testing.B) {
	combinedMatching := func(numPathsPerDomain int) func(i int, p *config.Policy) string {
		// returns a sequence of policies (ex: numPathsPerDomain=3)
		// https://*.foo.bar.test-0.example.com
		// https://*.foo.bar.test-0.example.com/foo/bar/path1
		// https://*.foo.bar.test-0.example.com/foo/bar/path2
		// https://*.foo.bar.test-1.example.com
		// https://*.foo.bar.test-1.example.com/foo/bar/path1
		// https://*.foo.bar.test-1.example.com/foo/bar/path2
		return func(i int, p *config.Policy) string {
			domain := fmt.Sprintf("https://*.foo.bar.test-%d.example.com", i/numPathsPerDomain)
			pathIdx := i % numPathsPerDomain
			var path string
			if pathIdx == 0 {
				path = ""
			} else {
				path = fmt.Sprintf("/foo/bar/path%d", pathIdx)
			}
			p.From = domain
			p.Path = path
			return domain + path
		}
	}

	b.Run("25 policies (5 domains, 5 paths per domain)", bench(combinedMatching(5), 25))
	b.Run("500 policies (50 domains, 10 paths per domain)", bench(combinedMatching(10), 500))
	b.Run("500 policies (10 domains, 50 paths per domain)", bench(combinedMatching(50), 500))
	b.Run("2500 policies (50 domains, 50 paths per domain)", bench(combinedMatching(50), 2500))
	b.Run("5000 policies (100 domains, 50 paths per domain)", bench(combinedMatching(50), 5000))
	b.Run("5000 policies (50 domains, 100 paths per domain)", bench(combinedMatching(100), 5000))
	b.Run("10000 policies (100 domains, 100 paths per domain)", bench(combinedMatching(100), 10000))
}

func BenchmarkGetIdentityProviderForRequestURL_New_DomainAndPrefixMatching(b *testing.B) {
	combinedMatching := func(numPathsPerDomain int) func(i int, p *config.Policy) string {
		// returns a sequence of policies (ex: numPathsPerDomain=3)
		// https://*.foo.bar.test-0.example.com/0
		// https://*.foo.bar.test-0.example.com/0/1
		// https://*.foo.bar.test-0.example.com/0/1/2
		// https://*.foo.bar.test-1.example.com/0
		// https://*.foo.bar.test-1.example.com/0/1
		// https://*.foo.bar.test-1.example.com/0/1/2
		return func(i int, p *config.Policy) string {
			domain := fmt.Sprintf("https://*.foo.bar.test-%d.example.com", i/numPathsPerDomain)
			pathIdx := i % numPathsPerDomain
			var prefix strings.Builder
			for j := 0; j <= pathIdx; j++ {
				fmt.Fprintf(&prefix, "/%d", j)
			}
			prefix.WriteString("/")
			p.From = domain
			p.Prefix = prefix.String()
			return domain + p.Prefix + "subpath"
		}
	}

	b.Run("25 policies (5 domains, 5 paths per domain)", bench(combinedMatching(5), 25))
	b.Run("500 policies (50 domains, 10 paths per domain)", bench(combinedMatching(10), 500))
	b.Run("500 policies (10 domains, 50 paths per domain)", bench(combinedMatching(50), 500))
	b.Run("2500 policies (50 domains, 50 paths per domain)", bench(combinedMatching(50), 2500))
	b.Run("5000 policies (100 domains, 50 paths per domain)", bench(combinedMatching(50), 5000))
	b.Run("5000 policies (50 domains, 100 paths per domain)", bench(combinedMatching(100), 5000))
	b.Run("10000 policies (100 domains, 100 paths per domain)", bench(combinedMatching(100), 10000))
}

func mustParseWeightedURLs(t testing.TB, urls ...string) []config.WeightedURL {
	wu, err := config.ParseWeightedUrls(urls...)
	require.NoError(t, err)
	return wu
}
