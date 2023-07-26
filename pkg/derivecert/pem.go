package derivecert

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// PEM representation of certificate authority data, serializable to JSON
type PEM struct {
	Cert []byte
	Key  []byte
}

// ToPEM converts private key and certificate into PEM representation
func ToPEM(key *ecdsa.PrivateKey, certDer []byte) (*PEM, error) {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal ecdsa private key: %w", err)
	}
	return &PEM{
		Key:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}),
		Cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer}),
	}, nil
}

// TLS parses PEM and returns TLS certificate
func (p *PEM) TLS() (tls.Certificate, error) {
	return tls.X509KeyPair(p.Cert, p.Key)
}

// KeyCert parses private key and cert from PEM encoded format
func (p *PEM) KeyCert() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	certDer, _ := pem.Decode(p.Cert)
	if certDer == nil {
		return nil, nil, fmt.Errorf("parse PEM cert")
	}
	keyDer, _ := pem.Decode(p.Key)
	if keyDer == nil {
		return nil, nil, fmt.Errorf("parse PEM key")
	}

	cert, err := x509.ParseCertificate(certDer.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse cert: %w", err)
	}
	key, err := x509.ParseECPrivateKey(keyDer.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse key: %w", err)
	}

	return key, cert, nil
}
