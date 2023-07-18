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

var isValidClientCertificateCache, _ = lru.New2Q[[4]string, bool](100)

func isValidClientCertificate(ca, crl string, certInfo ClientCertificateInfo) (bool, error) {
	// when ca is the empty string, client certificates are not required
	if ca == "" {
		return true, nil
	}

	cert := certInfo.Leaf
	intermediates := certInfo.Intermediates

	if cert == "" {
		return false, nil
	}

	cacheKey := [4]string{ca, crl, cert, intermediates}

	value, ok := isValidClientCertificateCache.Get(cacheKey)
	if ok {
		return value, nil
	}

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(ca))

	intermediatesPool := x509.NewCertPool()
	intermediatesPool.AppendCertsFromPEM([]byte(intermediates))

	xcert, err := parseCertificate(cert)
	if err != nil {
		return false, err
	}

	crls, err := parseCRLs([]byte(crl))
	if err != nil {
		return false, err
	}

	verifyErr := verifyClientCertificate(xcert, roots, intermediatesPool, crls)
	valid := verifyErr == nil

	if verifyErr != nil {
		log.Debug(context.Background()).Err(verifyErr).Msg("client certificate failed verification: %w")
	}

	isValidClientCertificateCache.Add(cacheKey, valid)

	return valid, nil
}

func verifyClientCertificate(
	cert *x509.Certificate,
	roots *x509.CertPool,
	intermediates *x509.CertPool,
	crls map[string]*x509.RevocationList,
) error {
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return err
	}

	// At least one of the verified chains must also pass revocation checking.
	err = errors.New("internal error: no verified chains")
	for _, chain := range chains {
		err = validateClientCertificateChain(chain, crls)
		if err == nil {
			return nil
		}
	}

	// Return an error from one of the chains that did not validate.
	// (In the common case there will be at most one verified chain.)
	return err
}

func validateClientCertificateChain(
	chain []*x509.Certificate,
	crls map[string]*x509.RevocationList,
) error {
	// Consult CRLs for all CAs in the chain (that is, all certificates except
	// for the first one). To match Envoy's behavior, if a CRL is provided for
	// any CA in the chain, CRLs must be provided for all CAs in the chain (see
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto).
	var anyIssuerHasCRL bool
	var lastIssuerWithoutCRL *x509.Certificate
	for i := 0; i < len(chain)-1; i++ {
		cert, issuer := chain[i], chain[i+1]
		crl := crls[string(issuer.RawSubject)]
		if crl == nil {
			lastIssuerWithoutCRL = issuer
			continue
		}

		anyIssuerHasCRL = true

		// Is the CRL signature itself valid?
		if err := crl.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("CRL signature verification failed for issuer %q: %w",
				issuer.Subject, err)
		}

		// Is the certificate listed as revoked in the CRL?
		for i := range crl.RevokedCertificates {
			if cert.SerialNumber.Cmp(crl.RevokedCertificates[i].SerialNumber) == 0 {
				return fmt.Errorf("certificate %q was revoked", cert.Subject)
			}
		}
	}

	if anyIssuerHasCRL && lastIssuerWithoutCRL != nil {
		return fmt.Errorf("no CRL provided for issuer %q", lastIssuerWithoutCRL.Subject)
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
