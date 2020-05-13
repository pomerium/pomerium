package cryptutil

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetCertificateForDomain(t *testing.T) {
	gen := func(t *testing.T, domain string) *tls.Certificate {
		cert, err := GenerateSelfSignedCertificate(domain)
		if !assert.NoError(t, err, "error generating certificate for: %s", domain) {
			t.FailNow()
		}
		return cert
	}

	t.Run("exact match", func(t *testing.T) {
		certs := []tls.Certificate{
			*gen(t, "a.example.com"),
			*gen(t, "b.example.com"),
		}

		found, err := GetCertificateForDomain(certs, "b.example.com")
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

		found, err := GetCertificateForDomain(certs, "b.example.com")
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, &certs[1], found)
	})
	t.Run("no name match", func(t *testing.T) {
		certs := []tls.Certificate{
			*gen(t, "a.example.com"),
		}

		found, err := GetCertificateForDomain(certs, "b.example.com")
		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, &certs[0], found)
	})
	t.Run("generate", func(t *testing.T) {
		certs := []tls.Certificate{}

		found, err := GetCertificateForDomain(certs, "b.example.com")
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, found)
	})
}
