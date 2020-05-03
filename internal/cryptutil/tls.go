package cryptutil

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/caddyserver/certmagic"
	"github.com/go-acme/lego/v3/challenge/tlsalpn01"
)

// NewAutocert automatically retrieves public certificates from the free
// lets encrypt certificate authority using the TLS-ALPN challenge per the ACME
// spec.
// Requires port 443, or at least packet forwarding from port 443.
func NewAutocert(hostnames []string, path string) (*tls.Config, error) {
	tlsConfig := defaultTLSConfig()
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.DisableHTTPChallenge = true
	cm := certmagic.NewDefault()
	cm.Storage = &certmagic.FileStorage{Path: path}

	// todo(bdd) : add cancellation context?
	if err := cm.ManageAsync(context.TODO(), hostnames); err != nil {
		return nil, fmt.Errorf("cryptutil: sync failed: %w", err)
	}
	tlsConfig.GetCertificate = cm.GetCertificate
	tlsConfig.NextProtos = append(tlsConfig.NextProtos, tlsalpn01.ACMETLS1Protocol)

	tlsConfig.BuildNameToCertificate()
	return tlsConfig, nil
}

// TLSConfigFromBase64 returns an tls configuration from a base64 encoded blob.
func TLSConfigFromBase64(cert, key string) (*tls.Config, error) {
	tlsConfig := defaultTLSConfig()
	c, err := CertifcateFromBase64(cert, key)
	if err != nil {
		return nil, err
	}
	tlsConfig.Certificates = []tls.Certificate{*c}
	tlsConfig.BuildNameToCertificate()
	return tlsConfig, nil
}

// TLSConfigFromFile returns an tls configuration from a certificate and
// key file .
func TLSConfigFromFile(cert, key string) (*tls.Config, error) {
	tlsConfig := defaultTLSConfig()
	c, err := CertificateFromFile(cert, key)
	if err != nil {
		return nil, err
	}
	tlsConfig.Certificates = []tls.Certificate{*c}
	tlsConfig.BuildNameToCertificate()
	return tlsConfig, nil
}

// TLSConfigFromFolder returns an tls configuration from a certificate and
// key file .
// func TLSConfigFromFolder(path string) (*tls.Config, error) {
// 	tlsConfig := defaultTLSConfig()
// 	c, err := CertificateFromFile(cert, key)
// 	if err != nil {
// 		return nil, err
// 	}
// 	tlsConfig.Certificates = []tls.Certificate{*c}
// 	tlsConfig.BuildNameToCertificate()
// 	return tlsConfig, nil
// }

// defaultTLSConfig returns an opinionated TLS configuration.
// See :
// https://wiki.mozilla.org/Security/Server_Side_TLS#Recommended_configurations
// https://blog.cloudflare.com/exposing-go-on-the-internet/
// https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices
// https://github.com/golang/go/blob/df91b8044dbe790c69c16058330f545be069cc1f/src/crypto/tls/common.go#L919
func defaultTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Prioritize cipher suites sped up by AES-NI (AES-GCM)
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: true,
		// Use curves which have assembly implementations
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		// HTTP/2 must be enabled manually when using http.Serve
		NextProtos: []string{"h2", "http/1.1"},
	}
}
