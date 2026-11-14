package outbound

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http/httpproxy"
)

func TestValidateProxyURL(t *testing.T) {
	t.Parallel()

	for _, rawURL := range []string{
		"",
		"proxy.example:3128",
		"user:secret@proxy.example:3128",
		"http://proxy.example:3128",
		"https://proxy.example",
		"socks5://proxy.example:1080",
		"http://[2001:db8::1]:3128",
		"http://[fe80::1%25eth0]:3128",
		"http://proxy.example:3128/",
		"proxy.example",
		"localhost:3128",
		"http://10.0.0.1:3128",
		"socks5h://proxy.example:1080",
		"http://user:p%40ss@proxy.example:3128",
		"HTTP://PROXY.EXAMPLE:3128",
		"http://proxy_host:3128",
		"http://proxy.example",
	} {
		assert.NoError(t, validateProxyURL(rawURL), rawURL)
	}
	creds := []string{"user", "secret", "proxy.example"}
	for _, tc := range []struct {
		rawURL string
		parts  []string // userinfo, host and scheme-position text of rawURL
	}{
		{"http://user:secret@[::1", []string{"user", "secret", "::1"}},
		{"http://user:secret#1@proxy.example:3128", creds},
		{"http://user:secret/1@proxy.example:3128", creds},
		{"ftp://user:secret@proxy.example:21", []string{"ftp", "user", "secret", "proxy.example"}},
		{"http://", nil},
		{"::::", []string{"::::"}},
		{"http://user:secret@proxy.example:0", creds},
		{"http://user:secret@proxy.example:99999", creds},
		{"http://user:secret@proxy.example:3128/path", creds},
		{"http://user:secret@proxy.example:3128?x=1", creds},
		{"http://user:secret@proxy.example:3128#f", creds},
		{"http://user:secret@pro$xy:3128", []string{"user", "secret", "pro$xy"}},
		{"http://user:p%zz@proxy.example:3128", []string{"user", "p%zz", "proxy.example"}},
		{"apikey123:x@proxy.example://y", []string{"apikey123", "proxy.example"}},
		{"http://proxy.example:3128 ", []string{"proxy.example"}},
	} {
		err := validateProxyURL(tc.rawURL)
		if assert.Error(t, err, tc.rawURL) {
			for _, part := range tc.parts {
				assert.NotContains(t, err.Error(), part, tc.rawURL)
			}
		}
	}
}

// TestValidateNoProxyAgreesWithHTTPProxy asserts that
// validateNoProxy accepts each entry for which httpproxy bypasses the
// proxy for a URL, and rejects, naming the entry, each entry for which
// httpproxy uses the proxy for that URL.
func TestValidateNoProxyAgreesWithHTTPProxy(t *testing.T) {
	t.Parallel()

	bypasses := func(t *testing.T, noProxy, rawURL string) bool {
		t.Helper()
		u, err := url.Parse(rawURL)
		require.NoError(t, err)
		proxyURL, err := (&httpproxy.Config{
			HTTPProxy:  "http://proxy.example:3128",
			HTTPSProxy: "http://proxy.example:3128",
			NoProxy:    noProxy,
		}).ProxyFunc()(u)
		require.NoError(t, err)
		return proxyURL == nil
	}

	for _, noProxy := range []string{"", " ", ",", " , "} {
		assert.NoError(t, validateNoProxy(noProxy), "%q", noProxy)
	}

	for _, tc := range []struct {
		noProxy, url string
		valid        bool
	}{
		{"*", "https://idp.example", true},
		{"localhost", "https://localhost", true},
		{"example.com", "https://example.com", true},
		{"example.com", "https://a.example.com", true},
		{".example.com", "https://a.example.com", true},
		{"*.example.com", "https://a.example.com", true},
		{"example.com:8443", "https://example.com:8443", true},
		{"example.com:", "https://example.com:8443", true},
		{"10.0.0.1", "https://10.0.0.1", true},
		{"10.0.0.1:8080", "http://10.0.0.1:8080", true},
		{"10.0.0.0/8", "https://10.1.2.3", true},
		{"::1", "https://[::1]", true},
		{"[::1]", "https://[::1]", true},
		{"[::1]:8080", "https://[::1]:8080", true},
		{"2001:db8::1", "https://[2001:db8::1]", true},
		{"[2001:db8::1]:8443", "https://[2001:db8::1]:8443", true},
		{"2001:db8::/32", "https://[2001:db8::5]", true},
		{"a.example, b.example", "https://b.example", true},
		{"a.example,,b.example", "https://b.example", true},
		{"a.example,", "https://a.example", true},
		{"  idp.example  ", "https://idp.example", true},
		{"IDP.Example", "https://idp.EXAMPLE", true},
		{"my_host.example", "https://my_host.example", true},
		{"bücher.example", "https://xn--bcher-kva.example", true},
		{"xn--bcher-kva.example", "https://bücher.example", true},
		{"https://idp.example", "https://idp.example", false},
		{"http://10.0.0.1", "https://10.0.0.1", false},
		{"idp.example/", "https://idp.example", false},
		{"idp.example/path", "https://idp.example", false},
		{"a.example idp.example", "https://idp.example", false},
		{"a.example;idp.example", "https://idp.example", false},
		{"a.example, b.example c.example", "https://c.example", false},
		{"user@idp.example", "https://idp.example", false},
		{"idp.example:https", "https://idp.example", false},
		{"idp.example:443:1", "https://idp.example", false},
		{"*idp.example", "https://idp.example", false},
		{"*:443", "https://idp.example", false},
		{"10.0.0.0/33", "https://10.0.0.1", false},
		{"10.0.0.0/8:443", "https://10.0.0.1", false},
		{":443", "https://idp.example", false},
	} {
		err := validateNoProxy(tc.noProxy)
		assert.Equal(t, tc.valid, err == nil, "%q is valid", tc.noProxy)
		if err != nil {
			assert.Contains(t, err.Error(), "entry ", tc.noProxy)
		}
		assert.Equal(t, tc.valid, bypasses(t, tc.noProxy, tc.url), "%q bypasses the proxy for %s", tc.noProxy, tc.url)
	}
}

// TestValidateProxyURLRejectsUnusableValues asserts that
// validateProxyURL rejects values that cannot name a proxy.
func TestValidateProxyURLRejectsUnusableValues(t *testing.T) {
	t.Parallel()

	for _, rawURL := range []string{
		"http//proxy.example:3128",
		"https:/proxy.example:3128",
		"$PROXY_URL",
		"http://proxy.example:99999",
	} {
		assert.Error(t, validateProxyURL(rawURL), rawURL)
	}
}

// TestValidateProxyURLErrors asserts what the validation errors say.
func TestValidateProxyURLErrors(t *testing.T) {
	t.Parallel()

	t.Run("no credentials advice without credentials", func(t *testing.T) {
		for _, rawURL := range []string{
			"http://proxy.example:3128 ",
			"http://proxy.example:abc",
			"http://a.example:3128,http://b.example:3128",
		} {
			err := validateProxyURL(rawURL)
			if assert.Error(t, err, rawURL) {
				assert.NotContains(t, err.Error(), "credentials", rawURL)
			}
		}
	})
	t.Run("credentials advice with credentials", func(t *testing.T) {
		err := validateProxyURL("http://user:p%zz@proxy.example:3128")
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "credentials must be percent-encoded")
		}
	})
	t.Run("no part of the value", func(t *testing.T) {
		err := validateProxyURL("apikey123:x@proxy.example://y")
		if assert.Error(t, err) {
			assert.NotContains(t, err.Error(), "apikey123")
			assert.Contains(t, err.Error(), "socks5h", "lists the supported schemes")
		}
	})
}
