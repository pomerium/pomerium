package cryptutil // import "github.com/pomerium/pomerium/internal/cryptutil"

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

func CertifcateFromBase64(cert, key string) (*tls.Certificate, error) {
	decodedCert, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate cert %v: %v", decodedCert, err)
	}
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate key %v: %v", decodedKey, err)
	}
	x509, err := tls.X509KeyPair(decodedCert, decodedKey)
	return &x509, err
}

func CertificateFromFile(certFile, keyFile string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	return &cert, err
}

func CertPoolFromBase64(encPemCerts string) (*x509.CertPool, error) {
	b, err := base64.StdEncoding.DecodeString(encPemCerts)
	if err != nil {
		return nil, fmt.Errorf("couldn't decode pem %v: %v", b, err)
	}
	return bytesToCertPool(b)
}

func CertPoolFromFile(pemFile string) (*x509.CertPool, error) {
	b, err := ioutil.ReadFile(pemFile)
	if err != nil {
		return nil, err
	}
	return bytesToCertPool(b)
}

func bytesToCertPool(b []byte) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(b); !ok {
		return nil, fmt.Errorf("could append certs from PEM")
	}
	return certPool, nil
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
