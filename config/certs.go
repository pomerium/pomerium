package config

import (
	"crypto/x509"
	"strings"
)

type certUsage byte
type certsIndex map[string]map[string]certUsage

const (
	certUsageServerAuth = certUsage(1 << iota)
	certUsageClientAuth
)

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

func (c certsIndex) addCert(cert *x509.Certificate) {
	usage := getCertUsage(cert)
	for _, name := range cert.DNSNames {
		c.add(name, usage)
	}
}

func (c certsIndex) matchCert(cert *x509.Certificate) (bool, string) {
	usage := getCertUsage(cert)
	for _, name := range cert.DNSNames {
		if c.match(name, usage) {
			return true, name
		}
	}
	return false, ""
}

func (c certsIndex) add(name string, usage certUsage) {
	prefix, suffix := splitDomainName(name)
	names := c[suffix]
	if names == nil {
		names = make(map[string]certUsage)
		c[suffix] = names
	}
	names[prefix] = usage
}

func (c certsIndex) match(name string, usage certUsage) bool {
	prefix, suffix := splitDomainName(name)
	names := c[suffix]
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
