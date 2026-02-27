package cryptutil

import (
	"crypto/x509"
	"strings"
)

type certUsage byte

const (
	certUsageServerAuth = certUsage(1 << iota)
	certUsageClientAuth
)

// A CertificatesIndex indexes certificates to determine if there is overlap between them.
type CertificatesIndex struct {
	index map[string]map[string]certUsage
}

// NewCertificatesIndex creates a new CertificatesIndex.
func NewCertificatesIndex() *CertificatesIndex {
	return &CertificatesIndex{
		index: make(map[string]map[string]certUsage),
	}
}

// Add adds a certificate to the index.
func (c *CertificatesIndex) Add(cert *x509.Certificate) {
	usage := getCertUsage(cert)
	for _, name := range cert.DNSNames {
		c.add(name, usage)
	}
}

// Delete deletes a certificate from the index.
func (c *CertificatesIndex) Delete(cert *x509.Certificate) {
	usage := getCertUsage(cert)
	for _, name := range cert.DNSNames {
		c.delete(name, usage)
	}
}

// OverlapsWithExistingCertificate returns true if the certificate overlaps with an existing certificate.
func (c *CertificatesIndex) OverlapsWithExistingCertificate(cert *x509.Certificate) (bool, string) {
	if c == nil {
		return false, ""
	}

	usage := getCertUsage(cert)
	for _, name := range cert.DNSNames {
		if c.match(name, usage) {
			return true, name
		}
	}
	return false, ""
}

func (c *CertificatesIndex) add(name string, usage certUsage) {
	prefix, suffix := splitDomainName(name)
	names := c.index[suffix]
	if names == nil {
		names = make(map[string]certUsage)
		c.index[suffix] = names
	}
	names[prefix] |= usage
}

func (c *CertificatesIndex) delete(name string, usage certUsage) {
	prefix, suffix := splitDomainName(name)
	names := c.index[suffix]
	usage = names[prefix] &^ usage
	if usage == 0 {
		delete(names, prefix)
	} else {
		names[prefix] = usage
	}
}

func (c *CertificatesIndex) match(name string, usage certUsage) bool {
	prefix, suffix := splitDomainName(name)
	names := c.index[suffix]
	if names == nil {
		return false
	}
	if prefix != "*" {
		return names["*"]&usage != 0 || names[prefix]&usage != 0
	}
	for _, u := range names {
		if u&usage != 0 {
			return true
		}
	}
	return false
}

func splitDomainName(name string) (prefix, suffix string) {
	dot := strings.IndexRune(name, '.')
	if dot < 0 {
		dot = 0 // i.e. `localhost`
	}
	return name[0:dot], name[dot:]
}

func getCertUsage(cert *x509.Certificate) certUsage {
	var usage certUsage
	for _, ex := range cert.ExtKeyUsage {
		switch ex {
		case x509.ExtKeyUsageClientAuth:
			usage |= certUsageClientAuth
		case x509.ExtKeyUsageServerAuth:
			usage |= certUsageServerAuth
		}
	}
	return usage
}
