package evaluator

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/pomerium/pomerium/internal/log"
)

var isValidClientCertificateCache, _ = lru.New2Q[[3]string, bool](100)

func isValidClientCertificate(ca, crl string, certInfo ClientCertificateInfo) (bool, error) {
	// when ca is the empty string, client certificates are not required
	if ca == "" {
		return true, nil
	}

	cert := certInfo.Leaf

	if cert == "" {
		return false, nil
	}

	cacheKey := [3]string{ca, crl, cert}

	value, ok := isValidClientCertificateCache.Get(cacheKey)
	if ok {
		return value, nil
	}

	roots, err := parseCertificates([]byte(ca))
	if err != nil {
		return false, err
	}

	xcert, err := parseCertificate(cert)
	if err != nil {
		return false, err
	}

	crls, err := parseCRLs([]byte(crl))
	if err != nil {
		return false, err
	}

	verifyErr := verifyClientCertificate(xcert, roots, crls)
	valid := verifyErr == nil

	if verifyErr != nil {
		log.Debug(context.Background()).Err(verifyErr).Msg("client certificate failed verification: %w")
	}

	isValidClientCertificateCache.Add(cacheKey, valid)

	return valid, nil
}

var errCertificateRevoked = errors.New("certificate revoked")

func verifyClientCertificate(
	cert *x509.Certificate,
	roots map[string]*x509.Certificate,
	crls map[string]*x509.RevocationList,
) error {
	rootPool := x509.NewCertPool()
	for _, root := range roots {
		rootPool.AddCert(root)
	}

	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     rootPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return err
	}

	// Consult any CRL for the presented certificate's Issuer.
	issuer := string(cert.RawIssuer)
	crl := crls[issuer]
	if crl == nil {
		return nil
	}

	// Do we have a corresponding trusted CA certificate?
	root, ok := roots[issuer]
	if !ok {
		return fmt.Errorf("could not check CRL: no matching trusted CA for issuer %s",
			cert.Issuer)
	}

	// Is the CRL signature itself valid?
	if err := crl.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("could not check CRL for issuer %s: signature verification "+
			"error: %w", cert.Issuer, err)
	}

	// Is the client certificate listed as revoked in this CRL?
	for i := range crl.RevokedCertificates {
		if cert.SerialNumber.Cmp(crl.RevokedCertificates[i].SerialNumber) == 0 {
			return errCertificateRevoked
		}
	}

	return nil
}

func parseCertificate(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("invalid certificate")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unknown PEM type: %s", block.Type)
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseCertificates(certs []byte) (map[string]*x509.Certificate, error) {
	m := make(map[string]*x509.Certificate)
	for {
		var block *pem.Block
		block, certs = pem.Decode(certs)
		if block == nil {
			return m, nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		m[string(cert.RawSubject)] = cert
	}
}

func parseCRLs(crl []byte) (map[string]*x509.RevocationList, error) {
	m := make(map[string]*x509.RevocationList)
	for {
		var block *pem.Block
		block, crl = pem.Decode(crl)
		if block == nil {
			return m, nil
		}
		if block.Type != "X509 CRL" {
			continue
		}
		l, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, err
		}
		m[string(l.RawIssuer)] = l
	}
}
