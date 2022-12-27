package cryptutil

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCertificateForServerName(t *testing.T) {
	gen := func(t *testing.T, serverName string) *tls.Certificate {
		cert, err := GenerateSelfSignedCertificate(serverName)
		if !assert.NoError(t, err, "error generating certificate for: %s", serverName) {
			t.FailNow()
		}
		return cert
	}

	t.Run("exact match", func(t *testing.T) {
		certs := []tls.Certificate{
			*gen(t, "a.example.com"),
			*gen(t, "b.example.com"),
		}

		found, err := GetCertificateForServerName(certs, "b.example.com")
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, &certs[1], found)
	})
	t.Run("wildcard match", func(t *testing.T) {
		certs := []tls.Certificate{
			*gen(t, "a.example.com"),
			*gen(t, "*.example.com"),
		}

		found, err := GetCertificateForServerName(certs, "b.example.com")
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, &certs[1], found)
	})
	t.Run("no name match", func(t *testing.T) {
		certs := []tls.Certificate{
			*gen(t, "a.example.com"),
		}

		found, err := GetCertificateForServerName(certs, "b.example.com")
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, found)
		assert.NotEqual(t, &certs[0], found)
	})
	t.Run("generate", func(t *testing.T) {
		certs := []tls.Certificate{}

		found, err := GetCertificateForServerName(certs, "b.example.com")
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, found)
	})
}

func TestGetCertificateServerNames(t *testing.T) {
	cert, err := GenerateSelfSignedCertificate("www.example.com")
	require.NoError(t, err)
	assert.Equal(t, []string{"www.example.com"}, GetCertificateServerNames(cert))
}
