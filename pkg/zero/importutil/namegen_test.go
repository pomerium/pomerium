package importutil_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/zero/importutil"
)

func TestGenerateCertName(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		input    x509.Certificate
		expected string
	}{
		{
			name: "cert with common name",
			input: x509.Certificate{
				IsCA:    true,
				Subject: pkix.Name{CommonName: "sample"},
			},
			expected: "sample",
		},
		{
			name: "cert with common name and other subject fields",
			input: x509.Certificate{
				IsCA: true,
				Subject: pkix.Name{
					CommonName:         "sample",
					Organization:       []string{"foo"},
					OrganizationalUnit: []string{"bar"},
				},
			},
			expected: "sample",
		},
		{
			name: "common name with spaces",
			input: x509.Certificate{
				IsCA:    true,
				Subject: pkix.Name{CommonName: "sample name"},
			},
			expected: "sample-name",
		},
		{
			name: "common name with special characters",
			input: x509.Certificate{
				IsCA:    true,
				Subject: pkix.Name{CommonName: "sample common-name"},
			},
			expected: "sample_common-name",
		},
		{
			name: "cert with other subject fields but no common name",
			input: x509.Certificate{
				IsCA: true,
				Subject: pkix.Name{
					Organization:       []string{"foo"},
					OrganizationalUnit: []string{"bar"},
				},
			},
			expected: "OU=bar,O=foo",
		},
		{
			name: "leaf cert with common name",
			input: x509.Certificate{
				IsCA:    false,
				Subject: pkix.Name{CommonName: "sample"},
			},
			expected: "sample",
		},
		{
			name: "leaf cert with dns name",
			input: x509.Certificate{
				IsCA:     false,
				DNSNames: []string{"example.com"},
			},
			expected: "example.com",
		},
		{
			name: "leaf cert with dns names",
			input: x509.Certificate{
				IsCA:     false,
				DNSNames: []string{"example.com", "*.example.com"},
			},
			expected: "*.example.com",
		},
		{
			name: "leaf cert with neither common name nor dns names",
			input: x509.Certificate{
				IsCA: false,
			},
			expected: "leaf",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nbf := time.Now()
			tc.input.NotBefore = nbf
			tc.expected += fmt.Sprintf("@%d", nbf.Unix())
			out := importutil.GenerateCertName(&tc.input)
			assert.Equal(t, tc.expected, *out)
		})
	}
}

func TestGenerateRouteNames(t *testing.T) {
	const testExample = "https://test.example.com"
	cases := []struct {
		name     string
		input    []*configpb.Route
		expected []string
	}{
		{
			name: "single domain name",
			input: []*configpb.Route{
				{From: "https://foo.example.com"},
				{From: "https://bar.example.com"},
				{From: "https://baz.example.com"},
			},
			expected: []string{"foo", "bar", "baz"},
		},
		{
			name: "multiple domain names, unique subdomains",
			input: []*configpb.Route{
				{From: "https://a.domain1.example.com"},
				{From: "https://b.domain1.example.com"},
				{From: "https://c.domain1.example.com"},
				{From: "https://d.domain2.example.com"},
				{From: "https://e.domain2.example.com"},
				{From: "https://f.domain2.example.com"},
			},
			expected: []string{"a", "b", "c", "d", "e", "f"},
		},
		{
			name: "multiple domain names, conflicting subdomains",
			input: []*configpb.Route{
				{From: "https://a.domain1.example.com"},
				{From: "https://b.domain1.example.com"},
				{From: "https://c.domain1.example.com"},
				{From: "https://a.domain2.example.com"},
				{From: "https://b.domain2.example.com"},
				{From: "https://c.domain2.example.com"},
			},
			expected: []string{
				"a-domain1",
				"b-domain1",
				"c-domain1",
				"a-domain2",
				"b-domain2",
				"c-domain2",
			},
		},
		{
			name: "multiple nested domain names, conflicting subdomains",
			input: []*configpb.Route{
				{From: "https://a.domain1.domain2.domain3.example.com"},
				{From: "https://b.domain1.domain2.domain3.example.com"},
				{From: "https://c.domain1.domain2.domain3.example.com"},
				{From: "https://a.domain1.domain2.domain4.example.com"},
				{From: "https://b.domain1.domain2.domain4.example.com"},
				{From: "https://c.domain1.domain2.domain4.example.com"},

				{From: "https://a.domain1.domain2.domain5.example.com"},
				{From: "https://b.domain2.domain2.domain5.example.com"},
				{From: "https://c.domain3.domain2.domain5.example.com"},
				{From: "https://a.domain1.domain2.domain6.example.com"},
				{From: "https://b.domain2.domain2.domain6.example.com"},
				{From: "https://c.domain3.domain2.domain6.example.com"},
			},
			expected: []string{
				"a-domain3",
				"b-domain3",
				"c-domain3",
				"a-domain4",
				"b-domain4",
				"c-domain4",

				"a-domain5",
				"b-domain5",
				"c-domain5",
				"a-domain6",
				"b-domain6",
				"c-domain6",
			},
		},
		{
			name: "conflicting subdomain names nested at different levels",
			input: []*configpb.Route{
				{From: "https://a.domain1.domain2.example.com"},
				{From: "https://a.domain1.example.com"},
				{From: "https://a.example.com"},
				{From: "https://a.domain3.domain2.example.com"},
				{From: "https://a.domain3.example.com"},
			},
			expected: []string{
				"a-domain2-domain1",
				"a-domain1",
				"a",
				"a-domain2-domain3",
				"a-domain3",
			},
		},
		{
			name: "conflicting subdomain names nested at different levels, unique paths",
			input: []*configpb.Route{
				{From: "https://a.domain1.domain2.example.com"},
				{From: "https://a.domain1.example.com"},
				{From: "https://a.example.com"},
			},
			expected: []string{
				"a-domain2-domain1",
				"a-domain1",
				"a",
			},
		},
		{
			name: "same domain, separate prefix options",
			input: []*configpb.Route{
				{From: testExample, Prefix: "/a"},
				{From: testExample, Prefix: "/b"},
				{From: testExample, Prefix: "/c"},
			},
			expected: []string{"test-a", "test-b", "test-c"},
		},
		{
			name: "same domain, mixed prefix/path options",
			input: []*configpb.Route{
				{From: testExample, Prefix: "/a"},
				{From: testExample, Path: "/b"},
				{From: testExample, Prefix: "/c"},
				{From: testExample, Path: "/d"},
			},
			expected: []string{"test-a", "test-b", "test-c", "test-d"},
		},
		{
			name: "same domain, name-conflicting prefix/path options (1 prefix/1 path)",
			input: []*configpb.Route{
				{From: testExample, Prefix: "/a/"},
				{From: testExample, Path: "/a"},
			},
			expected: []string{"test-a-prefix", "test-a"},
		},
		{
			name: "same domain, name-conflicting prefix/path options (more prefixes than paths)",
			input: []*configpb.Route{
				{From: testExample, Prefix: "/a/"},
				{From: testExample, Prefix: "/b/"},
				{From: testExample, Prefix: "/c/"},
				{From: testExample, Path: "/a"},
			},
			expected: []string{"test-a", "test-b", "test-c", "test-a-path"},
		},
		{
			name: "same domain, name-conflicting prefix/path options (more paths than prefixes)",
			input: []*configpb.Route{
				{From: testExample, Path: "/a"},
				{From: testExample, Path: "/b"},
				{From: testExample, Path: "/c"},
				{From: testExample, Prefix: "/a/"},
			},
			expected: []string{"test-a", "test-b", "test-c", "test-a-prefix"},
		},
		{
			name: "same domain, name-conflicting path options, duplicate names",
			input: []*configpb.Route{
				{From: testExample, Path: "/a"},
				{From: testExample, Path: "/a/"},
			},
			expected: []string{"test-a", "test-a (2)"},
		},
		{
			name: "same domain, name-conflicting prefix options, duplicate names",
			input: []*configpb.Route{
				{From: testExample, Prefix: "/a"},
				{From: testExample, Prefix: "/a/"},
			},
			expected: []string{"test-a", "test-a (2)"},
		},
		{
			name:     "missing domain name",
			input:    []*configpb.Route{{From: "https://:1234"}},
			expected: []string{"route-0"},
		},
		{
			name:     "invalid URL",
			input:    []*configpb.Route{{From: "https://\x7f"}},
			expected: []string{"route-0"},
		},
		{
			name: "regex paths",
			input: []*configpb.Route{
				{From: testExample, Regex: `/a/(.*)/b`},
				{From: testExample, Regex: `/a/(foo|bar)/b`},
				{From: testExample, Regex: `/(authorize.*|login|logout)`},
				{From: testExample, Regex: `/foo.+=-())(*+=,;:@~!'''-+_/.*`},
				{From: testExample, Regex: `/*`},
				{From: testExample, Regex: `/other/(.*)`},
				{From: testExample, Regex: `/other/.*`},
				{From: testExample, Regex: `/other/([^/]+)`},
				{From: testExample, Regex: `/other/([^/]*)`},
				{From: testExample, Regex: `/other/([^\/]+)`},
				{From: testExample, Regex: `/other/([^\/]*)`},
				{From: testExample, Regex: `/other/[^/]+`},
				{From: testExample, Regex: `/other/[^/]*`},
				{From: testExample, Regex: `/other/[^\/]+`},
				{From: testExample, Regex: `/other/[^\/]*`},
				{From: testExample, Regex: `/foo/bar/baz/.*`},
				{From: testExample, Regex: `/.*`},
				{From: testExample, Regex: `/.*`},
				{From: testExample, Regex: `/(.*)`},
				{From: testExample, Regex: `/.+`},
				{From: testExample, Regex: `/(.+)`},
				{From: testExample, Regex: `/([^/]+)`},
				{From: testExample, Regex: `/([^/]*)`},
				{From: testExample, Regex: `/([^\/]+)`},
				{From: testExample, Regex: `/([^\/]*)`},
				{From: testExample, Regex: `/[^/]+`},
				{From: testExample, Regex: `/[^/]*`},
				{From: testExample, Regex: `/[^\/]+`},
				{From: testExample, Regex: `/[^\/]*`},
				{From: testExample, Regex: `.+`},
				{From: testExample, Regex: `(.+)`},
				{From: testExample, Regex: `([^/]+)`},
				{From: testExample, Regex: `([^/]*)`},
				{From: testExample, Regex: `([^\/]+)`},
				{From: testExample, Regex: `([^\/]*)`},
				{From: testExample, Regex: `[^/]+`},
				{From: testExample, Regex: `[^/]*`},
				{From: testExample, Regex: `[^\/]+`},
				{From: testExample, Regex: `[^\/]*`},
				{From: testExample, Regex: `\w+`},
				{From: testExample, Regex: `\w*`},
				{From: testExample, Regex: `/\w+`},
				{From: testExample, Regex: `/\w*`},
				{From: testExample, Regex: `/(\w+)`},
				{From: testExample, Regex: `/(\w*)`},
				{From: testExample, Regex: `foo/.*`},
				{From: testExample, Regex: `/foo/.*`},
				{From: testExample, Regex: `/foo/\w+`},
				{From: testExample, Regex: `/foo/\w*`},
			},
			expected: slices.Collect(func(yield func(string) bool) {
				yield("test-re-1")
				yield("test-re-2")
				yield("test-re-3")
				yield("test-re-4")
				yield("test-re-5")
				yield("test-re-other-prefix")
				for i := 2; i <= 10; i++ {
					yield(fmt.Sprintf("test-re-other-prefix (%d)", i))
				}
				yield("test-re-foo-bar-baz-prefix")
				yield("test-re-any")
				for i := 2; i <= 29; i++ {
					yield(fmt.Sprintf("test-re-any (%d)", i))
				}
				yield("test-re-foo-prefix")
				yield("test-re-foo-prefix (2)")
				yield("test-re-foo-prefix (3)")
				yield("test-re-foo-prefix (4)")
			}),
		},
		{
			name: "duplicate routes",
			input: []*configpb.Route{
				{From: "https://route1.localhost.pomerium.io:8443"},
				{From: "https://route1.localhost.pomerium.io:8443"},
				{From: "https://route2.localhost.pomerium.io:8443"},
				{From: "https://route3.localhost.pomerium.io:8443"},
				{From: "https://route4.localhost.pomerium.io:8443"},
			},
			expected: []string{
				"route1",
				"route1 (2)",
				"route2",
				"route3",
				"route4",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, importutil.GenerateRouteNames(tc.input))
			policies := make([]*config.Policy, len(tc.input))
			for i := range tc.input {
				policies[i], _ = config.NewPolicyFromProto(tc.input[i])
			}
			assert.Equal(t, tc.expected, importutil.GenerateRouteNames(policies))
		})
	}
}
