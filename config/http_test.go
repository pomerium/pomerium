package config

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errProxyUsed = errors.New("proxy used")

func getLocalCertPEM(s *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: s.Certificate().Raw,
	})
}

// pinDefaultTransport installs the transport pkg/cmd/pomerium installs as
// http.DefaultTransport, with a Proxy that fails every request.
func pinDefaultTransport(t *testing.T) {
	t.Helper()
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	pinned := NewHTTPTransport(NewStaticSource(New(NewDefaultOptions())))
	pinned.Proxy = func(*http.Request) (*url.URL, error) { return nil, errProxyUsed }
	http.DefaultTransport = pinned
}

func assertInheritsDefaults(t *testing.T, transport *http.Transport) {
	t.Helper()
	assert.NotZero(t, transport.IdleConnTimeout, "IdleConnTimeout")
	assert.NotZero(t, transport.MaxIdleConns, "MaxIdleConns")
	assert.NotZero(t, transport.TLSHandshakeTimeout, "TLSHandshakeTimeout")
	assert.NotZero(t, transport.ExpectContinueTimeout, "ExpectContinueTimeout")
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
	assertInheritsDefaults(t, transport)
	assert.True(t, transport.ForceAttemptHTTP2)

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
	t.Run("inherits defaults", func(t *testing.T) {
		transport := NewPolicyHTTPTransport(&Options{}, &Policy{TLSSkipVerify: true}, false)
		assertInheritsDefaults(t, transport.(*http.Transport))
	})
}

func TestGetTLSClientTransport(t *testing.T) {
	pinDefaultTransport(t)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(s.Close)

	transport, err := GetTLSClientTransport(New(&Options{
		CA: base64.StdEncoding.EncodeToString(getLocalCertPEM(s)),
	}))
	require.NoError(t, err)
	assertInheritsDefaults(t, transport)
	assert.Nil(t, transport.Proxy)

	res, err := (&http.Client{Transport: transport}).Get(s.URL)
	require.NoError(t, err)
	_ = res.Body.Close()
}
