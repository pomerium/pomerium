//go:build ignore

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"time"
)

// Returns a new self-signed certificate, as both PEM data and an
// *x509.Certificate, along with the corresponding private key.
func newSelfSignedCertificate(template *x509.Certificate) (
	string, *x509.Certificate, *ecdsa.PrivateKey,
) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalln(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		log.Fatalln(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatalln(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), cert, key
}

// Returns a new certificate, as both PEM data and an *x509.Certificate, along
// with the new certificate's corresponding private key.
func newCertificate(template, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey) (
	string, *x509.Certificate, *ecdsa.PrivateKey,
) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalln(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), issuerKey)
	if err != nil {
		log.Fatalln(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Fatalln(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), cert, key
}

// Returns a new CRL in PEM format.
func newCRL(
	template *x509.RevocationList, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey,
) string {
	der, err := x509.CreateRevocationList(rand.Reader, template, issuer, issuerKey)
	if err != nil {
		log.Fatalln(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))
}

// Generates new test certificates and CRLs.
func main() {
	notAfter := time.Now().Add(3650 * 24 * time.Hour)

	rootPEM, rootCA, rootKey := newSelfSignedCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(0x1000),
		Subject: pkix.Name{
			CommonName: "Trusted Root CA",
		},
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	})

	trustedClientCertPEM, _, _ := newCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(0x1001),
		Subject: pkix.Name{
			CommonName: "trusted client cert",
		},
		NotAfter:    notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, rootCA, rootKey)

	_, untrustedCA, untrustedCAKey := newSelfSignedCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(0x1000),
		Subject: pkix.Name{
			CommonName: "Untrusted Root CA",
		},
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  true,
	})

	untrustedClientCertPEM, _, _ := newCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(0x1001),
		Subject: pkix.Name{
			CommonName: "untrusted client cert",
		},
		NotAfter:    notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, untrustedCA, untrustedCAKey)

	revokedClientCertPEM, revokedClientCert, _ := newCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(0x1002),
		Subject: pkix.Name{
			CommonName: "revoked client cert",
		},
		NotAfter:    notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, rootCA, rootKey)

	crlPEM := newCRL(&x509.RevocationList{
		Number: big.NewInt(0x2000),
		RevokedCertificates: []pkix.RevokedCertificate{
			{
				SerialNumber:   revokedClientCert.SerialNumber,
				RevocationTime: time.Now(),
			},
		},
	}, rootCA, rootKey)

	fmt.Println(`
const (
	testCA = ` + "`\n" + rootPEM + "`" + `
	testValidCert = ` + "`\n" + trustedClientCertPEM + "`" + `
	testUntrustedCert = ` + "`\n" + untrustedClientCertPEM + "`" + `
	testRevokedCert = ` + "`\n" + revokedClientCertPEM + "`" + `
	testCRL = ` + "`\n" + crlPEM + "`" + `
)
`)
}
