package cryptutil // import "github.com/pomerium/pomerium/internal/cryptutil"

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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
