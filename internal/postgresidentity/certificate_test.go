package postgresidentity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseAndValidateCertificatePEM(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	valid := newTestCertificatePEM(t, now, func(*x509.Certificate) {})

	identity, err := ParseAndValidateCertificatePEM(valid, "DB.EXAMPLE.COM.", now)
	require.NoError(t, err)
	require.Equal(t, BindingIDFromFingerprint(identity.Fingerprint[:]), identity.BindingID)
	require.NotEmpty(t, identity.BindingID)

	tests := []struct {
		name   string
		mutate func(*x509.Certificate)
		want   string
	}{
		{"wrong route SAN", func(c *x509.Certificate) { c.DNSNames = []string{"other.example.com"} }, "route hostname"},
		{"wildcard route SAN", func(c *x509.Certificate) { c.DNSNames = []string{"*.example.com"} }, "route hostname"},
		{"expired", func(c *x509.Certificate) { c.NotAfter = now }, "not currently valid"},
		{"future", func(c *x509.Certificate) { c.NotBefore = now.Add(time.Second) }, "not currently valid"},
		{"long lived", func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(66 * time.Minute) }, "exceeds 65 minutes"},
		{"certificate authority", func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage = x509.KeyUsageCertSign }, "non-CA"},
		{"server auth", func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} }, "client authentication"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseAndValidateCertificatePEM(newTestCertificatePEM(t, now, tc.mutate), "db.example.com", now)
			require.ErrorContains(t, err, tc.want)
		})
	}

	t.Run("multiple certificates", func(t *testing.T) {
		_, err := ParseAndValidateCertificatePEM(append(valid, valid...), "db.example.com", now)
		require.ErrorContains(t, err, "exactly one")
	})
}

func TestBindingIDFromFingerprint(t *testing.T) {
	require.Empty(t, BindingIDFromFingerprint([]byte("short")))
	require.Equal(t,
		"postgrescert-SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		BindingIDFromFingerprint(make([]byte, 32)))
}

func newTestCertificatePEM(t testing.TB, now time.Time, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pomerium-postgres-client"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"db.example.com"},
	}
	mutate(template)
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
