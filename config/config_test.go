package config

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	t.Run("generate for specific name", func(t *testing.T) {
		cfg := &Config{Options: NewDefaultOptions()}
		cfg.Options.DeriveInternalDomainCert = proto.String("databroker.int.example.com")

		ok, err := cfg.WillHaveCertificateForServerName("databroker.int.example.com")
		require.NoError(t, err)
		assert.True(t, ok)

		found, err := cfg.GetCertificateForServerName("databroker.int.example.com")
		require.NoError(t, err)
		assert.True(t, cryptutil.MatchesServerName(found, "databroker.int.example.com"))

		certPool, err := cfg.GetCertificatePool()
		require.NoError(t, err)

		xc, err := x509.ParseCertificate(found.Certificate[0])
		require.NoError(t, err)

		_, err = xc.Verify(x509.VerifyOptions{
			DNSName:   "databroker.int.example.com",
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			Roots:     certPool,
		})
		require.NoError(t, err)
	})
}
