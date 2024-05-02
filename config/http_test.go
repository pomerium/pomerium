package config

import (
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
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

	src := NewStaticSource(&Config{
		Options: &Options{
			CA: base64.StdEncoding.EncodeToString(getLocalCertPEM(s)),
		},
	})
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
	src := NewStaticSource(&Config{Options: &Options{}})
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
