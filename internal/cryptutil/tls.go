package cryptutil

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/caddyserver/certmagic"
)

// GetCertificateForDomain returns the tls Certificate which matches the given domain name.
// It should handle both exact matches and wildcard matches. If none of those match, the first certificate will be used.
// Finally if there are no matching certificates one will be generated.
func GetCertificateForDomain(certificates []tls.Certificate, domain string) (*tls.Certificate, error) {
	// first try a direct name match
	for _, cert := range certificates {
		if matchesDomain(&cert, domain) {
			return &cert, nil
		}
	}

	// next use the first cert
	if len(certificates) > 0 {
		return &certificates[0], nil
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
