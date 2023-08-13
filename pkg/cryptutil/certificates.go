package cryptutil

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/pomerium/pomerium/pkg/derivecert"
)

const (
	maxCertFileSize = 1 << 16
)

// CertificateFromBase64 returns an X509 pair from a base64 encoded blob.
func CertificateFromBase64(cert, key string) (*tls.Certificate, error) {
	decodedCert, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate cert %v: %w", decodedCert, err)
	}
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate key %v: %w", decodedKey, err)
	}
	x509, err := tls.X509KeyPair(decodedCert, decodedKey)
	return &x509, err
}

// CertificateFromFile given a certificate, and key file path, returns a X509
// keypair.
func CertificateFromFile(certFile, keyFile string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	return &cert, err
}

// ParseCRLs parses PEM-encoded certificate revocation lists, returning a map
// of the parsed CRLs keyed by the raw issuer name.
func ParseCRLs(crl []byte) (map[string]*x509.RevocationList, error) {
	m := make(map[string]*x509.RevocationList)
	for {
		var block *pem.Block
		block, crl = pem.Decode(crl)
		if block == nil {
			if len(crl) > 0 {
				return nil, errors.New("cryptutil: non-PEM data in CRL bundle")
			}
			return m, nil
		}
		if block.Type != "X509 CRL" {
			continue
		}
		l, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("cryptutil: failed to parse crl: %w", err)
		}
		m[string(l.RawIssuer)] = l
	}
}

// DecodePublicKey decodes a PEM-encoded ECDSA public key.
func DecodePublicKey(encodedKey []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(encodedKey)
	if block == nil {
		return nil, fmt.Errorf("cryptutil: decoded nil PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("cryptutil: data was not an ECDSA public key")
	}

	return ecdsaPub, nil
}

// EncodePublicKey encodes an ECDSA public key to PEM format.
func EncodePublicKey(key *ecdsa.PublicKey) ([]byte, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(block), nil
}

// DecodePrivateKey decodes a PEM-encoded ECDSA private key.
func DecodePrivateKey(encodedKey []byte) (*ecdsa.PrivateKey, error) {
	var skippedTypes []string
	var block *pem.Block

	for {
		block, encodedKey = pem.Decode(encodedKey)

		if block == nil {
			return nil, fmt.Errorf("cryptutil: failed to find EC PRIVATE KEY in PEM data after skipping types %v", skippedTypes)
		}

		if block.Type == "EC PRIVATE KEY" {
			break
		}

		skippedTypes = append(skippedTypes, block.Type)
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

// EncodePrivateKey encodes an ECDSA private key to PEM format.
func EncodePrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	derKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	keyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derKey,
	}

	return pem.EncodeToMemory(keyBlock), nil
}

// GenerateCertificate generates a TLS certificate derived from a shared key.
func GenerateCertificate(sharedKey []byte, domain string, configure ...func(*x509.Certificate)) (*tls.Certificate, error) {
	ca, err := derivecert.NewCA(sharedKey)
	if err != nil {
		return nil, fmt.Errorf("cryptutil: failed to generate certificate, error deriving CA: %w", err)
	}

	pem, err := ca.NewServerCert([]string{domain}, configure...)
	if err != nil {
		return nil, fmt.Errorf("cryptutil: failed to generate certificate, error creating server certificate: %w", err)
	}

	tlsCert, err := pem.TLS()
	if err != nil {
		return nil, fmt.Errorf("cryptutil: failed to generate certificate, error converting server certificate to TLS certificate: %w", err)
	}

	return &tlsCert, nil
}

// EncodeCertificate encodes a TLS certificate into PEM compatible byte slices.
// Returns `nil`, `nil` if there is an error marshaling the PKCS8 private key.
func EncodeCertificate(cert *tls.Certificate) (pemCertificateBytes, pemKeyBytes []byte, err error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, nil, nil
	}
	publicKeyBytes := cert.Certificate[0]
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: publicKeyBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}), nil
}

// ParsePEMCertificate parses a PEM encoded certificate block.
func ParsePEMCertificate(raw []byte) (*x509.Certificate, error) {
	data := raw
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid certificate: %w", err)
		}
		return cert, nil
	}
	return nil, fmt.Errorf("no certificate block found")
}

// ParsePEMCertificateFromBase64 parses a PEM encoded certificate block from a base64 encoded string.
func ParsePEMCertificateFromBase64(encoded string) (*x509.Certificate, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return ParsePEMCertificate(raw)
}

// ParsePEMCertificateFromFile decodes a PEM certificate from a file.
func ParsePEMCertificateFromFile(file string) (*x509.Certificate, error) {
	fd, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer func() {
		_ = fd.Close()
	}()
	raw, err := io.ReadAll(io.LimitReader(fd, maxCertFileSize))
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return ParsePEMCertificate(raw)
}
