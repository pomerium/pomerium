package derivecert_test

import (
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/derivecert"
)

// TestCA creates two CA instances from same PSK
// and asserts that they yield same private key,
// and a certificate created by one CA is trusted by another
func TestCA(t *testing.T) {
	psk := make([]byte, 32)
	_, err := rand.Read(psk)
	require.NoError(t, err)

	for i := 0; i < 100; i++ {
		ca1, err := derivecert.NewCA(psk)
		require.NoError(t, err)
		ca2, err := derivecert.NewCA(psk)
		require.NoError(t, err)

		ca1PEM, err := ca2.PEM()
		require.NoError(t, err)
		ca2PEM, err := ca2.PEM()
		require.NoError(t, err)

		assert.Equal(t, ca1PEM.Key, ca2PEM.Key)

		serverPEM, err := ca1.NewServerCert([]string{"myserver.com"})
		require.NoError(t, err)

		_, serverCert, err := serverPEM.KeyCert()
		require.NoError(t, err)

		pool := x509.NewCertPool()
		require.True(t, pool.AppendCertsFromPEM(ca2PEM.Cert))

		opts := x509.VerifyOptions{
			Roots:         pool,
			DNSName:       "myserver.com",
			Intermediates: x509.NewCertPool(),
		}

		_, err = serverCert.Verify(opts)
		require.NoError(t, err)
	}
}
