package config_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// NB: we omit the https:// prefix in test urls so the fuzzer doesn't consider it
// part of the input. in the real system, we can assume any actual request urls
// have the valid https scheme (otherwise they wouldn't get here in the first place)
var corpus = []string{
	"example.com",
	"example.com",
	"example.com/",
	"example.com/",
	"example.com/foo",
	"example.com/bar/baz",
	"example.com/hello/world",
	"example.com/foo/bar/baz/qux",
	"example.com/search?q=test",
	"example.com/search?q=test&page=2",
	"example.com/filter?category=books&price=low",
	"example.com/api/v1/users?id=123",
	"example.com/page#section1",
	"example.com/docs#installation",
	"example.com/#top",
	"example.com/articles#readmore",
	"example.com/%20space",
	"example.com/~user/profile",
	"example.com/emoji/😊",
	"example.com/path%2Fwith%2Fencoded%2Fcharacters",
	"example.com:8080",
	"example.com:443",
	"localhost:3000",
	"127.0.0.1:8443",
	"user:pass@example.com",
	"user:pass@example.com/secure",
	"[2001:db8::1]",
	"[2001:db8::1]:8080/path",
	"例子.测试",
	"उदाहरण.परीक्षा",
	"example.com/" + strings.Repeat("a", 2048),
	"example.com/path/" + strings.Repeat("b", 1024),
	"example.com/?",
	"example.com/?=",
	"example.com/?q=%C3%A9",
	"example.com/space%20in%20path",
	"example.com/multiple?query=params&another=test",
	"example.com/case/SENSITIVE",
	"example.com/a/b/c/d/e/f/g/h/i",
	"example.com/nested/path/with/many/levels",
	"example.com/foo/bar;param=value",
	"example.com/bar?foo=bar&baz=qux",
	"example.com/path with spaces",
	"example.com/#fragment",
	"example.com:1234/path",
	"example.com/path/to/resource?query=param#fragment",
	"example.com/file.tar.gz",
	"example.com/some%20path/?query=with%20space",
	"example.com/api/resource/123?format=json",
	"example.com/api/v2/resource/456?fields=foo,bar,baz",
	"example.com/user/1/profile",
	"example.com/posts/2023/06/21/title",
	"example.com/item/123/edit",
	"example.com/items?filter=active",
	"example.com/login?redirect=/home",
	"example.com/register?next=/dashboard",
	"example.com/download/file.zip",
	"example.com/upload/image.jpg",
	"example.com/api/data?page=2&sort=asc",
	"example.com/products?category=electronics",
	"example.com/categories/?name=books",
	"example.com/search?query=open+source",
	"example.com/redirect?to=https://example.org",
	"example.com/profile/settings",
	"test.com/foo",
	"mysite.org/bar/baz",
	"localhost:3000/test",
	"dev.local/hello/world",
	"subdomain.example.com/api/v1/resource",
	"example.net/foo/bar/baz",
	"mysite.dev/hello/world",
	"myapp.local/api/resource/123",
	"example.edu/search?q=test",
	"example.co.uk/filter?category=books&price=low",
	"example.org/page#section1",
	"example.net/docs#installation",
	"example.io/#top",
	"example.biz/articles#readmore",
	"example.info/%20space",
	"example.tv/~user/profile",
	"example.xyz/emoji/😊",
	"example.online/path%2Fwith%2Fencoded%2Fcharacters",
	"example.shop:8080",
	"example.club:443",
	"localhost:8080/test/path",
	"127.0.0.1:3000/test",
	"user:pass@mysite.com",
	"user:pass@secure.example.com",
	"[2001:db8::1234]/path",
	"[2001:db8::5678]:8080/path/to/resource",
	"xn--fsq.com/emoji/😊",
	"xn--g6w251d.com/space%20path",
	"xn--80akhbyknj4f.com/%20space",
	"xn--d1acufc.xn--p1ai/",
	"xn--80asehdb/xn--b1afkhbi.com/",
	"xn--e1afmkfd.xn--p1ai",
	"xn--fct.xn--q9jyb4c/xn--node%20path",
	"xn--fiq228c.xn--kpry57d/%20encoded%2Fcharacters",
	"xn--fsq6x.com/path%20with%20spaces",
	"xn--g2xx48c/xn--g2xx48c/#fragment",
}

func FuzzGetIdentityProviderForRequestURL(f *testing.F) {
	for _, input := range corpus {
		f.Add(input)
	}

	emptyPortMatchesAll := true // todo

	type testCase struct {
		policy *config.Policy
		check  func(input *url.URL) (bool, error)
	}

	checkEmptyPort := func(u *url.URL) bool {
		if !emptyPortMatchesAll {
			// flag disabled
			if port := u.Port(); port != "" && port != "443" {
				// should not match any non-default port
				return false
			}
		}
		return true
	}

	testCases := []testCase{
		{
			policy: &config.Policy{From: "https://example.com"},
			check: func(input *url.URL) (bool, error) {
				if !checkEmptyPort(input) {
					return false, nil
				}

				if input.Hostname() != "example.com" {
					return false, nil
				}
				return true, nil
			},
		},
		{
			policy: &config.Policy{From: "https://*.foo.example.com", Prefix: "/prefix"},
			check: func(u *url.URL) (bool, error) {
				if !checkEmptyPort(u) {
					return false, nil
				}

				parts := strings.Split(u.Hostname(), ".")
				if len(parts) != 4 {
					return false, nil
				}
				if len(parts[0]) == 0 {
					return false, nil
				}
				if parts[1] != "foo" || parts[2] != "example" || parts[3] != "com" {
					return false, nil
				}
				if !strings.HasPrefix(u.Path, "/prefix") {
					return false, nil
				}
				return true, nil
			},
		},
	}

	options := config.NewDefaultOptions()
	sharedKey := cryptutil.NewKey()
	options.SharedKey = base64.StdEncoding.EncodeToString(sharedKey)
	options.InsecureServer = true
	options.Provider = "oidc"
	options.ProviderURL = "https://oidc.example.com"
	options.ClientID = "client_id"
	options.ClientSecret = "client_secret"
	options.RuntimeFlags = config.DefaultRuntimeFlags()
	if emptyPortMatchesAll {
		options.RuntimeFlags[config.RuntimeFlagMatchAnyIncomingPort] = false
	}

	for i, tc := range testCases {
		tc.policy.To = mustParseWeightedURLs(f, fmt.Sprintf("https://to-%d", i))
		tc.policy.IDPClientID = fmt.Sprintf("client_id_%d", i)
		tc.policy.IDPClientSecret = fmt.Sprintf("client_secret_%d", i)
		options.Policies = append(options.Policies, *tc.policy)
	}
	require.NoError(f, options.Validate())

	cache, err := config.NewPolicyCache(options)
	require.NoError(f, err)

	f.Fuzz(func(t *testing.T, input string) {
		input = "https://" + input // see note at the top of this file
		inputURL, err := urlutil.ParseAndValidateURL(input)
		if err != nil {
			t.SkipNow()
		}

		for i, tc := range testCases {
			expected := tc.policy

			actualIdp, actualErr := cache.GetIdentityProviderForRequestURL(options, input)
			expectedMatch, expectedErr := tc.check(inputURL)
			actualErrIsNotFound := errors.Is(actualErr, config.ErrNoIdentityProviderFound)

			if expectedErr != nil {
				if actualErrIsNotFound {
					t.Fatalf("expected invalid input %q to be rejected", input)
					return
				}
				assert.Errorf(t, actualErr, "expected an error for input %q", input)
			} else {
				if actualErr != nil && !actualErrIsNotFound {
					t.Fatalf("unexpected error: %v", err)
					return
				}
				if expectedMatch {
					if actualErrIsNotFound {
						t.Fatalf("expected policy %d to match for input %q", i, input)
						return
					}
					assert.Equalf(t, expected.IDPClientID, actualIdp.ClientId, "wrong client id for input %q", input)
				} else {
					if !actualErrIsNotFound {
						assert.NotEqualf(t, expected.IDPClientID, actualIdp.ClientId, "expected policy %d not to match input %q", i, input)
					}
				}
			}
		}
	})
}
