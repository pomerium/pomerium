//go:build ignore

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/url"
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

// Returns a raw SubjectAltName extension with a single UserPrincipalName.
func newSANUserPrincipalName(upnValue string) []byte {
	type UPN struct {
		UTF8String string `asn1:"utf8"`
	}
	type OtherName struct {
		OID   asn1.ObjectIdentifier
		Value UPN `asn1:"tag:0"`
	}
	type GeneralNames struct {
		OtherName OtherName `asn1:"tag:0"`
	}
	san, err := asn1.Marshal(GeneralNames{
		OtherName: OtherName{
			OID: asn1.ObjectIdentifier{
				1, 3, 6, 1, 4, 1, 311, 20, 2, 3},
			Value: UPN{
				UTF8String: upnValue,
			},
		},
	})
	if err != nil {
		log.Fatalln(err)
	}
	return san
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

	intermediatePEM, intermediateCA, intermediateKey := newCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(0x1003),
		Subject: pkix.Name{
			CommonName: "Trusted Intermediate CA",
		},
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, rootCA, rootKey)

	trustedClientCert2PEM, _, _ := newCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(0x1000),
		Subject: pkix.Name{
			CommonName: "client cert from intermediate",
		},
		NotAfter:    notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, intermediateCA, intermediateKey)

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

	trustedClientCert3PEM, _, _ := newCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(0x1004),
		Subject: pkix.Name{
			CommonName: "client cert 3",
		},
		DNSNames:    []string{"a.client3.example.com", "b.client3.example.com"},
		NotAfter:    notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, rootCA, rootKey)

	trustedClientCert4PEM, _, _ := newCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(0x1005),
		Subject: pkix.Name{
			CommonName: "client cert 4",
		},
		EmailAddresses: []string{"client4@example.com"},
		NotAfter:       notAfter,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, rootCA, rootKey)

	trustedClientCert5PEM, _, _ := newCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(0x1006),
		Subject: pkix.Name{
			CommonName: "client cert 5",
		},
		IPAddresses: []net.IP{net.ParseIP("192.168.10.10")},
		NotAfter:    notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, rootCA, rootKey)

	trustedClientCert6PEM, _, _ := newCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(0x1007),
		Subject: pkix.Name{
			CommonName: "client cert 6",
		},
		URIs:        []*url.URL{{Scheme: "spiffe", Host: "example.com", Path: "/foo/bar"}},
		NotAfter:    notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, rootCA, rootKey)

	trustedClientCert7PEM, _, _ := newCertificate(&x509.Certificate{
		SerialNumber: big.NewInt(0x1007),
		Subject: pkix.Name{
			CommonName: "client cert 7",
		},
		NotAfter:    notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17},
			Value: newSANUserPrincipalName("test_device"),
		}},
	}, rootCA, rootKey)

	fmt.Println(`
const (
	testCA = ` + "`\n" + rootPEM + "`" + `
	testValidCert = ` + "`\n" + trustedClientCertPEM + "`" + `
	testUntrustedCert = ` + "`\n" + untrustedClientCertPEM + "`" + `
	testRevokedCert = ` + "`\n" + revokedClientCertPEM + "`" + `
	testCRL = ` + "`\n" + crlPEM + "`" + `
	testIntermediateCA = ` + "`\n" + intermediatePEM + "`" + `
	testValidIntermediateCert = ` + "`\n" + trustedClientCert2PEM + "`" + `
	testValidCertWithDNSSANs = ` + "`\n" + trustedClientCert3PEM + "`" + `
	testValidCertWithEmailSAN = ` + "`\n" + trustedClientCert4PEM + "`" + `
	testValidCertWithIPSAN = ` + "`\n" + trustedClientCert5PEM + "`" + `
	testValidCertWithURISAN = ` + "`\n" + trustedClientCert6PEM + "`" + `
	testValidCertWithUPNSAN = ` + "`\n" + trustedClientCert7PEM + "`" + `
)
`)
}
