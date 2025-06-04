package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A Certificate is the public and private certificate details.
type Certificate struct {
	X509          *x509.Certificate
	PublicDER     []byte
	PublicPEM     []byte
	PrivateKey    *ecdsa.PrivateKey
	PrivateKeyDER []byte
	PrivateKeyPEM []byte
}

// GenerateCertificateChain generates a root certificate authority, an intermediate certificate authority and a certificate.
func GenerateCertificateChain(tb testing.TB) (rootCA, intermediateCA, cert Certificate) {
	tb.Helper()

	var err error

	rootCA.PrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)
	intermediateCA.PrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)
	cert.PrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)

	notAfter := time.Now().Add(3650 * 24 * time.Hour)
	rootCATemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0x1000),
		Subject: pkix.Name{
			CommonName: "Root CA",
		},
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	intermediateCATemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0x1001),
		Subject: pkix.Name{
			CommonName: "Intermediate CA",
		},
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(0x1002),
		Subject: pkix.Name{
			CommonName: "Certificate",
		},
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	rootCA.PrivateKeyDER, err = x509.MarshalPKCS8PrivateKey(rootCA.PrivateKey)
	require.NoError(tb, err)
	rootCA.PublicDER, err = x509.CreateCertificate(rand.Reader, rootCATemplate, rootCATemplate, rootCA.PrivateKey.Public(), rootCA.PrivateKey)
	require.NoError(tb, err)
	rootCA.X509, err = x509.ParseCertificate(rootCA.PublicDER)
	require.NoError(tb, err)
	rootCA.PublicPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCA.PublicDER, Headers: map[string]string{"name": "root certificate"}})

	rootCA.PrivateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rootCA.PrivateKeyDER})
	intermediateCA.PrivateKeyDER, err = x509.MarshalPKCS8PrivateKey(intermediateCA.PrivateKey)
	require.NoError(tb, err)
	intermediateCA.PrivateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: intermediateCA.PrivateKeyDER, Headers: map[string]string{"name": "intermediate key"}})
	intermediateCA.PublicDER, err = x509.CreateCertificate(rand.Reader, intermediateCATemplate, rootCA.X509, intermediateCA.PrivateKey.Public(), rootCA.PrivateKey)
	require.NoError(tb, err)
	intermediateCA.X509, err = x509.ParseCertificate(intermediateCA.PublicDER)
	require.NoError(tb, err)
	intermediateCA.PublicPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateCA.PublicDER, Headers: map[string]string{"name": "intermediate certificate"}})

	cert.PrivateKeyDER, err = x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	require.NoError(tb, err)
	cert.PrivateKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: cert.PrivateKeyDER, Headers: map[string]string{"name": "key"}})
	cert.PublicDER, err = x509.CreateCertificate(rand.Reader, certTemplate, intermediateCA.X509, cert.PrivateKey.Public(), intermediateCA.PrivateKey)
	require.NoError(tb, err)
	cert.X509, err = x509.ParseCertificate(cert.PublicDER)
	require.NoError(tb, err)
	cert.PublicPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.PublicDER, Headers: map[string]string{"name": "certificate"}})

	return rootCA, intermediateCA, cert
}
