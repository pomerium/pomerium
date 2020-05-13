package cryptutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"

	"github.com/caddyserver/certmagic"
	"github.com/go-acme/lego/v3/challenge/tlsalpn01"
)

// NewAutocert automatically retrieves public certificates from the free
// certificate authority Let's Encrypt using HTTP-01 and TLS-ALPN-01 challenges.
// To complete the challenges, the server must be accessible from the internet
// by port 80 or 443 .
//
// https://letsencrypt.org/docs/challenge-types/#http-01-challenge
// https://letsencrypt.org/docs/challenge-types/#tls-alpn-01
func NewAutocert(tlsConfig *tls.Config, hostnames []string, useStaging bool, path string) (*tls.Config, func(h http.Handler) http.Handler, error) {
	certmagic.DefaultACME.Agreed = true
	if useStaging {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	}
	cm := certmagic.NewDefault()

	tlsConfig = newTLSConfigIfEmpty(tlsConfig)
	// add existing certs to the cache, and staple OCSP
	for _, cert := range tlsConfig.Certificates {
		if err := cm.CacheUnmanagedTLSCertificate(cert, nil); err != nil {
			return nil, nil, fmt.Errorf("cryptutil: failed caching cert: %w", err)
		}
	}
	cm.Storage = &certmagic.FileStorage{Path: path}
	acmeConfig := certmagic.NewACMEManager(cm, certmagic.DefaultACME)
	cm.Issuer = acmeConfig
	// todo(bdd) : add cancellation context?
	if err := cm.ManageAsync(context.TODO(), hostnames); err != nil {
		return nil, nil, fmt.Errorf("cryptutil: sync failed: %w", err)
	}

	tlsConfig.GetCertificate = cm.GetCertificate
	tlsConfig.NextProtos = append(tlsConfig.NextProtos, tlsalpn01.ACMETLS1Protocol)
	tlsConfig.BuildNameToCertificate()
	return tlsConfig, acmeConfig.HTTPChallengeHandler, nil
}

// TLSConfigFromBase64 returns an tls configuration from a base64 encoded blob.
func TLSConfigFromBase64(tlsConfig *tls.Config, cert, key string) (*tls.Config, error) {
	tlsConfig = newTLSConfigIfEmpty(tlsConfig)
	c, err := CertifcateFromBase64(cert, key)
	if err != nil {
		return nil, err
	}
	tlsConfig.Certificates = append(tlsConfig.Certificates, *c)
	tlsConfig.BuildNameToCertificate()
	return tlsConfig, nil
}

// TLSConfigFromFile returns an tls configuration from a certificate and
// key file .
func TLSConfigFromFile(tlsConfig *tls.Config, cert, key string) (*tls.Config, error) {
	tlsConfig = newTLSConfigIfEmpty(tlsConfig)
	c, err := CertificateFromFile(cert, key)
	if err != nil {
		return nil, err
	}
	tlsConfig.Certificates = append(tlsConfig.Certificates, *c)
	tlsConfig.BuildNameToCertificate()
	return tlsConfig, nil
}

// newTLSConfigIfEmpty returns an opinionated TLS configuration if config is nil.
// See :
// https://wiki.mozilla.org/Security/Server_Side_TLS#Recommended_configurations
// https://blog.cloudflare.com/exposing-go-on-the-internet/
// https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices
// https://github.com/golang/go/blob/df91b8044dbe790c69c16058330f545be069cc1f/src/crypto/tls/common.go#L919
func newTLSConfigIfEmpty(tlsConfig *tls.Config) *tls.Config {
	if tlsConfig != nil {
		return tlsConfig
	}
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

// GetCertificateForDomain returns the tls Certificate which matches the given domain name.
// It should handle both exact matches and wildcard matches. If none of those match, the first certificate will be used.
// Finally if there are no matching certificates one will be generated.
func GetCertificateForDomain(cfg *tls.Config, domain string) (*tls.Certificate, error) {
	// first try a direct name match
	for _, cert := range cfg.Certificates {
		if matchesDomain(&cert, domain) {
			return &cert, nil
		}
	}

	// next use the first cert
	if len(cfg.Certificates) > 0 {
		return &cfg.Certificates[0], nil
	}

	// finally fall back to a generated, self-signed certificate
	return GenerateSelfSignedCertificate(domain)
}

func matchesDomain(cert *tls.Certificate, domain string) bool {
	if cert == nil || len(cert.Certificate) == 0 {
		return false
	}

	xcert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return false
	}

	if certmagic.MatchWildcard(domain, xcert.Subject.CommonName) {
		return true
	}

	for _, san := range xcert.DNSNames {
		if certmagic.MatchWildcard(domain, san) {
			return true
		}
	}

	return false
}
