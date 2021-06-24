package cryptutil

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	crlPemType      = "X509 CRL"
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

// CRLFromBase64 parses a certificate revocation list from a base64 encoded blob.
func CRLFromBase64(rawCRL string) (*pkix.CertificateList, error) {
	bs, err := base64.StdEncoding.DecodeString(rawCRL)
	if err != nil {
		return nil, fmt.Errorf("cryptutil: failed to decode base64 crl: %w", err)
	}
	return DecodeCRL(bs)
}

// CRLFromFile parses a certificate revocation list from a file.
func CRLFromFile(fileName string) (*pkix.CertificateList, error) {
	bs, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("cryptutil: failed to read crl file (%s): %w", fileName, err)
	}
	return DecodeCRL(bs)
}

// DecodeCRL decodes a PEM-encoded certificate revocation list.
func DecodeCRL(encodedCRL []byte) (*pkix.CertificateList, error) {
	data := encodedCRL
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type == crlPemType {
			lst, err := x509.ParseDERCRL(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("cryptutil: failed to parse crl: %w", err)
			}
			return lst, nil
		}
	}
	return nil, fmt.Errorf("cryptutil: invalid crl, no %s block found", crlPemType)
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
		} else {
			skippedTypes = append(skippedTypes, block.Type)
			continue
		}
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

// GenerateSelfSignedCertificate generates a self-signed TLS certificate.
//
// mostly copied from https://golang.org/src/crypto/tls/generate_cert.go
func GenerateSelfSignedCertificate(domain string) (*tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to geneate private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Pomerium"},
		},
		NotBefore:             time.Now().Add(-time.Minute * 10),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, domain)
	}

	publicKeyBytes, err := x509.CreateCertificate(rand.Reader,
		&template, &template,
		privateKey.Public(), privateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: publicKeyBytes}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to convert x509 bytes into tls certificate: %w", err)
	}

	return &cert, nil
}

// ParsePEMCertificate parses PEM encoded certificate block
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

// ParsePEMCertificateFromFile decodes PEM certificate from file
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
