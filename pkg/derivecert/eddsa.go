package derivecert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
)

type Ed25519CA struct {
	key  ed25519.PrivateKey
	cert *x509.Certificate
}

func NewEd25519CA(prng io.Reader) (*Ed25519CA, error) {
	_, key, err := ed25519.GenerateKey(prng)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(0x1000),
		Subject: pkix.Name{
			Organization: []string{"Pomerium"},
			CommonName:   "Pomerium PSK CA",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return &Ed25519CA{
		key:  key,
		cert: cert,
	}, nil
}

// PEM returns the CA certificate in PEM format.
func (ca *Ed25519CA) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}

func (ca *Ed25519CA) NewServerCertificate(dnsNames []string, ipAddresses []net.IP) (*tls.Certificate, error) {
	return ca.newCertificate(x509.ExtKeyUsageServerAuth, dnsNames, ipAddresses)
}

func (ca *Ed25519CA) NewClientCertificate() (*tls.Certificate, error) {
	return ca.newCertificate(x509.ExtKeyUsageClientAuth, nil, nil)
}

func (ca *Ed25519CA) newCertificate(
	extKeyUsage x509.ExtKeyUsage,
	dnsNames []string,
	ipAddresses []net.IP,
) (*tls.Certificate, error) {
	var serialBytes [20]byte
	if _, err := rand.Read(serialBytes[:]); err != nil {
		return nil, err
	}
	serial := new(big.Int).SetBytes(serialBytes[:])

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"Pomerium"}},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{extKeyUsage},
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, key.Public(), ca.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        cert,
	}, nil
}
