package config

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestConfig_GetCertificateForServerName(t *testing.T) {
	gen := func(t *testing.T, serverName string) *tls.Certificate {
		cert, err := cryptutil.GenerateCertificate(nil, serverName)
		if !assert.NoError(t, err, "error generating certificate for: %s", serverName) {
			t.FailNow()
		}
		return cert
	}

	t.Run("exact match", func(t *testing.T) {
		cfg := &Config{Options: NewDefaultOptions(), AutoCertificates: []tls.Certificate{
			*gen(t, "a.example.com"),
			*gen(t, "b.example.com"),
		}}

		found, err := cfg.GetCertificateForServerName("b.example.com")
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, &cfg.AutoCertificates[1], found)
	})
	t.Run("wildcard match", func(t *testing.T) {
		cfg := &Config{Options: NewDefaultOptions(), AutoCertificates: []tls.Certificate{
			*gen(t, "a.example.com"),
			*gen(t, "*.example.com"),
		}}

		found, err := cfg.GetCertificateForServerName("b.example.com")
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, &cfg.AutoCertificates[1], found)
	})
	t.Run("no name match", func(t *testing.T) {
		cfg := &Config{Options: NewDefaultOptions(), AutoCertificates: []tls.Certificate{
			*gen(t, "a.example.com"),
		}}

		found, err := cfg.GetCertificateForServerName("b.example.com")
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, found)
		assert.NotEqual(t, &cfg.AutoCertificates[0], found)
	})
	t.Run("generate", func(t *testing.T) {
		cfg := &Config{Options: NewDefaultOptions()}

		found, err := cfg.GetCertificateForServerName("b.example.com")
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, found)
	})
}
