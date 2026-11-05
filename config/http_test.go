package config

import (
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/nullable"
)

func getLocalCertPEM(s *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: s.Certificate().Raw,
	})
}

func TestHTTPTransport(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()

	src := NewStaticSource(New(&Options{
		CA: base64.StdEncoding.EncodeToString(getLocalCertPEM(s)),
	}))
	transport := NewHTTPTransport(src)
	client := &http.Client{
		Transport: transport,
	}
	_, err := client.Get(s.URL)
	assert.NoError(t, err)
}

func TestPolicyHTTPTransport(t *testing.T) {
	originalTransport := http.DefaultTransport
	defer func() {
		http.DefaultTransport = originalTransport
	}()
	src := NewStaticSource(New(&Options{}))
	http.DefaultTransport = NewHTTPTransport(src)

	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()

	get := func(options *Options, policy *Policy) (*http.Response, error) {
		transport := NewPolicyHTTPTransport(options, policy, false)
		client := &http.Client{
			Transport: transport,
		}
		return client.Get(s.URL)
	}

	t.Run("default", func(t *testing.T) {
		_, err := get(&Options{}, &Policy{})
		assert.Error(t, err)
	})
	t.Run("skip verify", func(t *testing.T) {
		_, err := get(&Options{}, &Policy{TLSSkipVerify: true})
		assert.NoError(t, err)
	})
	t.Run("ca", func(t *testing.T) {
		_, err := get(&Options{
			CA: base64.StdEncoding.EncodeToString(getLocalCertPEM(s)),
		}, &Policy{})
		assert.NoError(t, err)
	})
	t.Run("custom ca", func(t *testing.T) {
		_, err := get(&Options{}, &Policy{
			TLSCustomCA: base64.StdEncoding.EncodeToString(getLocalCertPEM(s)),
		})
		assert.NoError(t, err)
	})
}

func TestOutboundProxyFunc(t *testing.T) {
	for _, key := range []string{"http_proxy", "https_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD"} {
		t.Setenv(key, "")
	}
	t.Setenv("HTTP_PROXY", "http://env-http.example:3128")
	t.Setenv("HTTPS_PROXY", "http://env-https.example:3128")

	for _, tc := range []struct {
		name    string
		options GlobalOptions
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
			options: GlobalOptions{OutboundHttpsProxy: nullable.From("http://proxy.example:3128")},
			url:     "https://idp.example/token",
			expect:  "http://proxy.example:3128",
		},
		{
			name:    "http proxy",
			options: GlobalOptions{OutboundHttpProxy: nullable.From("http://proxy.example:3128")},
			url:     "http://idp.example/token",
			expect:  "http://proxy.example:3128",
		},
		{
			name:    "https proxy only",
			options: GlobalOptions{OutboundHttpsProxy: nullable.From("http://proxy.example:3128")},
			url:     "http://idp.example/token",
		},
		{
			name:    "empty https proxy",
			options: GlobalOptions{OutboundHttpsProxy: nullable.From("")},
			url:     "https://idp.example/token",
		},
		{
			name:    "no proxy only",
			options: GlobalOptions{OutboundNoProxy: nullable.From("other.example")},
			url:     "https://idp.example/token",
		},
		{
			name:    "no proxy match",
			options: GlobalOptions{OutboundHttpsProxy: nullable.From("http://proxy.example:3128"), OutboundNoProxy: nullable.From(".internal.example")},
			url:     "https://idp.internal.example/token",
		},
		{
			name:    "no proxy mismatch",
			options: GlobalOptions{OutboundHttpsProxy: nullable.From("http://proxy.example:3128"), OutboundNoProxy: nullable.From(".internal.example")},
			url:     "https://idp.example/token",
			expect:  "http://proxy.example:3128",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			proxyURL, err := outboundProxyFunc(&Options{GlobalOptions: tc.options})(req)
			require.NoError(t, err)
			if tc.expect == "" {
				assert.Nil(t, proxyURL)
			} else if assert.NotNil(t, proxyURL) {
				assert.Equal(t, tc.expect, proxyURL.String())
			}
		})
	}
}

func TestValidateOutboundProxyURL(t *testing.T) {
	t.Parallel()

	for _, rawURL := range []string{
		"",
		"proxy.example:3128",
		"user:secret@proxy.example:3128",
		"http://proxy.example:3128",
		"https://proxy.example",
		"socks5://proxy.example:1080",
		"http://[2001:db8::1]:3128",
	} {
		assert.NoError(t, validateOutboundProxyURL(rawURL), rawURL)
	}
	for _, rawURL := range []string{
		"http://user:secret@[::1",
		"http://user:secret#1@proxy.example:3128",
		"http://user:secret/1@proxy.example:3128",
		"ftp://user:secret@proxy.example:21",
		"http://",
		"::::",
	} {
		err := validateOutboundProxyURL(rawURL)
		if assert.Error(t, err, rawURL) {
			assert.NotContains(t, err.Error(), "secret")
		}
	}
}
