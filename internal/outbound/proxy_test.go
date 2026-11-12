package outbound

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/outbound/outboundtest"
	"github.com/pomerium/pomerium/pkg/nullable"
)

// proxyFunc returns the proxy function for the outbound proxy options o.
func proxyFunc(o ProxyOptions) func(*http.Request) (*url.URL, error) {
	return ProxySettings(o).proxyFunc()
}

func TestProxyConfig(t *testing.T) {
	outboundtest.ClearProxyEnv(t)
	t.Setenv("HTTP_PROXY", "http://env-http.example:3128")
	t.Setenv("HTTPS_PROXY", "http://env-https.example:3128")

	for _, tc := range []struct {
		name    string
		options ProxyOptions
		url     string
		expect  string
	}{
		{
			name:   "environment https proxy",
			url:    "https://idp.example/token",
			expect: "http://env-https.example:3128",
		},
		{
			name:   "environment http proxy",
			url:    "http://idp.example/token",
			expect: "http://env-http.example:3128",
		},
		{
			name:    "https proxy",
			options: ProxyOptions{HTTPSProxy: nullable.From("http://proxy.example:3128")},
			url:     "https://idp.example/token",
			expect:  "http://proxy.example:3128",
		},
		{
			name:    "http proxy",
			options: ProxyOptions{HTTPProxy: nullable.From("http://proxy.example:3128")},
			url:     "http://idp.example/token",
			expect:  "http://proxy.example:3128",
		},
		{
			name:    "https proxy only",
			options: ProxyOptions{HTTPSProxy: nullable.From("http://proxy.example:3128")},
			url:     "http://idp.example/token",
		},
		{
			name:    "empty https proxy",
			options: ProxyOptions{HTTPSProxy: nullable.From("")},
			url:     "https://idp.example/token",
		},
		{
			name:    "no proxy only",
			options: ProxyOptions{NoProxy: nullable.From("other.example")},
			url:     "https://idp.example/token",
		},
		{
			name:    "no proxy match",
			options: ProxyOptions{HTTPSProxy: nullable.From("http://proxy.example:3128"), NoProxy: nullable.From(".internal.example")},
			url:     "https://idp.internal.example/token",
		},
		{
			name:    "no proxy mismatch",
			options: ProxyOptions{HTTPSProxy: nullable.From("http://proxy.example:3128"), NoProxy: nullable.From(".internal.example")},
			url:     "https://idp.example/token",
			expect:  "http://proxy.example:3128",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			proxyURL, err := proxyFunc(tc.options)(req)
			require.NoError(t, err)
			if tc.expect == "" {
				assert.Nil(t, proxyURL)
			} else if assert.NotNil(t, proxyURL) {
				assert.Equal(t, tc.expect, proxyURL.String())
			}
		})
	}
}

// TestProxyConfigInvalidProxy asserts that an unparsable proxy option
// does not result in requests being sent without a proxy.
func TestProxyConfigInvalidProxy(t *testing.T) {
	t.Parallel()

	for _, rawURL := range []string{
		" http://proxy.example:3128",
		"http://user:p%ZZ@proxy.example:3128",
	} {
		o := ProxyOptions{HTTPSProxy: nullable.From(rawURL)}
		proxyURL, err := proxyFunc(o)(httptest.NewRequest(http.MethodGet, "https://idp.example/token", nil))
		assert.True(t, err != nil || proxyURL != nil, "%q: request is sent without a proxy", rawURL)
	}
}

// TestProxyConfigInvalidProxyEnvironment asserts that, without outbound
// proxy options, an unparsable HTTPS_PROXY results in no proxy and no error.
func TestProxyConfigInvalidProxyEnvironment(t *testing.T) {
	outboundtest.ClearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", " http://proxy.example:3128")

	proxyURL, err := proxyFunc(ProxyOptions{})(httptest.NewRequest(http.MethodGet, "https://idp.example/token", nil))
	assert.NoError(t, err)
	assert.Nil(t, proxyURL)
}

// TestProxyOptionsReplaceEnvironment covers cases of "the options
// replace the environment as a whole" that TestProxyConfig does not.
func TestProxyOptionsReplaceEnvironment(t *testing.T) {
	outboundtest.ClearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "http://env-https.example:3128")
	t.Setenv("NO_PROXY", "idp.example")

	get := func(o ProxyOptions) string {
		proxyURL, err := proxyFunc(o)(httptest.NewRequest(http.MethodGet, "https://idp.example/token", nil))
		require.NoError(t, err)
		if proxyURL == nil {
			return ""
		}
		return proxyURL.String()
	}

	assert.Equal(t, "", get(ProxyOptions{}), "environment NO_PROXY applies without options")
	assert.Equal(t, "http://proxy.example:3128", get(ProxyOptions{HTTPSProxy: nullable.From("http://proxy.example:3128")}),
		"environment NO_PROXY is not combined with outbound_https_proxy")
	assert.Equal(t, "", get(ProxyOptions{HTTPProxy: nullable.From("")}), "empty outbound_http_proxy")
	assert.Equal(t, "", get(ProxyOptions{NoProxy: nullable.From("")}), "empty outbound_no_proxy")

	assert.NoError(t, validateProxyURL("socks5h://proxy.example:1080"))
	assert.Error(t, validateProxyURL("socks4://proxy.example:1080"))
}
