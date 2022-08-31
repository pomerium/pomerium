package cryptutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/caddyserver/certmagic"

	"github.com/pomerium/pomerium/internal/log"
)

// GetCertPool gets a cert pool for the given CA or CAFile.
func GetCertPool(ca, caFile string) (*x509.CertPool, error) {
	ctx := context.TODO()
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		log.Error(ctx).Err(err).Msg("pkg/cryptutil: failed getting system cert pool making new one")
		rootCAs = x509.NewCertPool()
	}
	if ca == "" && caFile == "" {
		return rootCAs, nil
	}

	var data []byte
	if ca != "" {
		data, err = base64.StdEncoding.DecodeString(ca)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64-encoded certificate authority: %w", err)
		}
	} else {
		data, err = os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate authority file (%s): %w", caFile, err)
		}
	}
	if ok := rootCAs.AppendCertsFromPEM(data); !ok {
		return nil, fmt.Errorf("failed to append any PEM-encoded certificates")
	}
	log.Debug(ctx).Msg("pkg/cryptutil: added custom certificate authority")
	return rootCAs, nil
}

// GetCertificateForDomain returns the tls Certificate which matches the given domain name.
// It should handle both exact matches and wildcard matches. If none of those match, the first certificate will be used.
// Finally if there are no matching certificates one will be generated.
func GetCertificateForDomain(certificates []tls.Certificate, domain string) (*tls.Certificate, error) {
	// first try a direct name match
	for i := range certificates {
		if matchesDomain(&certificates[i], domain) {
			return &certificates[i], nil
		}
	}

	log.Error(context.Background()).
		Str("domain", domain).
		Msg("cryptutil: no TLS certificate found for domain, using self-signed certificate")

	// finally fall back to a generated, self-signed certificate
	return GenerateSelfSignedCertificate(domain)
}

// GetCertificateDomains gets all the certificate's matching domain names.
// Will return an empty slice if certificate is nil, empty, or x509 parsing fails.
func GetCertificateDomains(cert *tls.Certificate) []string {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil
	}

	xcert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil
	}

	var domains []string
	if xcert.Subject.CommonName != "" {
		domains = append(domains, xcert.Subject.CommonName)
	}
	for _, dnsName := range xcert.DNSNames {
		if dnsName != "" {
			domains = append(domains, dnsName)
		}
	}
	return domains
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
