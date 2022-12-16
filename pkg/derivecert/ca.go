package derivecert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"time"

	"golang.org/x/crypto/hkdf"
)

// CA is certificate authority
type CA struct {
	// key is signing key
	key *ecdsa.PrivateKey
	// cert is a CA certificate
	cert *x509.Certificate
}

func mustParseDate(d string) time.Time {
	t, err := time.Parse("2006-Jan-02", d)
	if err != nil {
		panic(err)
	}
	return t
}

var (
	notBefore = mustParseDate("2022-Dec-01")
	notAfter  = mustParseDate("2050-Dec-01")
)

// NewCA creates new certificate authority using a pre-shared key.
// This certificate authority is generated on the fly
// and would yield the same private key every time for the given PSK.
//
// That allows services that have a certain pre-shared key (i.e. shared_secret)
// to have automatic TLS without need to share and distribute certs,
// and provides a better alternative to plaintext communication,
// but is not a replacement for proper mTLS.
func NewCA(psk []byte) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), pskRandReader(psk))
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	cert, err := caCertTemplate(psk)
	if err != nil {
		return nil, err
	}

	der, err := x509.CreateCertificate(pskRandReader(psk), cert, cert, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}

	if cert, err = x509.ParseCertificate(der); err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	ca := &CA{key, cert}

	return ca, nil
}

// CAFromPEM loads CA from PEM encoded data
func CAFromPEM(p PEM) (*CA, string, error) {
	key, cert, err := p.KeyCert()
	if err != nil {
		return nil, "", fmt.Errorf("decode key, cert: %w", err)
	}
	ca := CA{key: key, cert: cert}

	return &ca, ca.cert.Subject.CommonName, nil
}

// NewServerCert generates certificate for the given domain name(s)
func (ca *CA) NewServerCert(domains []string) (*PEM, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	tmpl, err := serverCertTemplate(domains)
	if err != nil {
		return nil, fmt.Errorf("cert template: %w", err)
	}

	cert, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, key.Public(), ca.key)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}

	return ToPEM(key, cert)
}

// PEM returns PEM-encoded cert and key
func (ca *CA) PEM() (*PEM, error) {
	return ToPEM(ca.key, ca.cert.Raw)
}

func pskRandReader(psk []byte) io.Reader {
	return hkdf.New(sha256.New, psk, nil, nil)
}

func caCertTemplate(psk []byte) (*x509.Certificate, error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Pomerium"}, CommonName: "Pomerium PSK CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil
}

func serverCertTemplate(domains []string) (*x509.Certificate, error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	return &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"Pomerium"}, CommonName: "Pomerium PSK domain cert"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     domains,
	}, nil
}

// Key returns CA private key
func (ca *CA) Key() *ecdsa.PrivateKey {
	return ca.key
}

func newSerial() (*big.Int, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	return serialNumber, nil
}
