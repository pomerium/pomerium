package evaluator

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

// ClientCertConstraints contains additional constraints to validate when
// verifying a client certificate.
type ClientCertConstraints struct {
	// MaxVerifyDepth is the maximum allowed certificate chain depth (not
	// counting the leaf certificate). A value of 0 indicates no maximum.
	MaxVerifyDepth uint32

	// SANMatchers is a map of SAN type to regex match expression. When
	// non-empty, a client certificate must contain at least one Subject
	// Alternative Name that matches one of the expessions.
	SANMatchers SANMatchers
}

// SANMatchers is a map of SAN type to regex match expression.
type SANMatchers = map[config.SANType]*regexp.Regexp

// ClientCertConstraintsFromConfig populates a new ClientCertConstraints struct
// based on the provided configuration.
func ClientCertConstraintsFromConfig(
	cfg *config.DownstreamMTLSSettings,
) (*ClientCertConstraints, error) {
	constraints := &ClientCertConstraints{
		MaxVerifyDepth: cfg.GetMaxVerifyDepth(),
	}

	// Combine all SAN match patterns for a given type into one expression.
	patternsByType := make(map[config.SANType][]string)
	for i := range cfg.MatchSubjectAltNames {
		m := &cfg.MatchSubjectAltNames[i]
		patternsByType[m.Type] = append(patternsByType[m.Type], m.Pattern)
	}
	matchers := make(SANMatchers)
	for k, v := range patternsByType {
		var s strings.Builder
		s.WriteString("^(")
		s.WriteString(v[0])
		for _, p := range v[1:] {
			s.WriteString(")|(")
			s.WriteString(p)
		}
		s.WriteString(")$")
		r, err := regexp.Compile(s.String())
		if err != nil {
			return nil, err
		}
		matchers[k] = r
	}
	if len(matchers) > 0 {
		constraints.SANMatchers = matchers
	}

	return constraints, nil
}

var isValidClientCertificateCache, _ = lru.New2Q[[5]string, bool](100)

func isValidClientCertificate(
	ca, crl string, certInfo ClientCertificateInfo, constraints ClientCertConstraints,
) (bool, error) {
	// when ca is the empty string, client certificates are not required
	if ca == "" {
		return true, nil
	}

	cert := certInfo.Leaf
	intermediates := certInfo.Intermediates

	if cert == "" {
		return false, nil
	}

	constraintsJSON, err := json.Marshal(constraints)
	if err != nil {
		return false, fmt.Errorf("internal error: failed to serialize constraints: %w", err)
	}

	cacheKey := [5]string{ca, crl, cert, intermediates, string(constraintsJSON)}

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

	crls, err := cryptutil.ParseCRLs([]byte(crl))
	if err != nil {
		return false, err
	}

	verifyErr := verifyClientCertificate(xcert, roots, intermediatesPool, crls, constraints)
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
	constraints ClientCertConstraints,
) error {
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return err
	}

	// At least one of the verified chains must also pass revocation checking
	// and satisfy any additional constraints.
	err = errors.New("internal error: no verified chains")
	for _, chain := range chains {
		err = validateClientCertificateChain(chain, crls, constraints)
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
	constraints ClientCertConstraints,
) error {
	if constraints.MaxVerifyDepth > 0 {
		if d := uint32(len(chain) - 1); d > constraints.MaxVerifyDepth {
			return fmt.Errorf("chain depth %d exceeds max_verify_depth %d",
				d, constraints.MaxVerifyDepth)
		}
	}

	if err := validateClientCertificateSANs(chain, constraints.SANMatchers); err != nil {
		return err
	}

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

var errNoSANMatch = errors.New("no matching Subject Alternative Name")

func validateClientCertificateSANs(chain []*x509.Certificate, matchers SANMatchers) error {
	if len(matchers) == 0 {
		return nil
	} else if len(chain) == 0 {
		return errors.New("internal error: no certificates in verified chain")
	}

	cert := chain[0]

	if r := matchers[config.SANTypeDNS]; r != nil {
		for _, name := range cert.DNSNames {
			if r.MatchString(name) {
				return nil
			}
		}
	}
	if r := matchers[config.SANTypeEmail]; r != nil {
		for _, email := range cert.EmailAddresses {
			if r.MatchString(email) {
				return nil
			}
		}
	}
	if r := matchers[config.SANTypeIPAddress]; r != nil {
		for _, ip := range cert.IPAddresses {
			if r.MatchString(ip.String()) {
				return nil
			}
		}
	}
	if r := matchers[config.SANTypeURI]; r != nil {
		for _, uri := range cert.URIs {
			if r.MatchString(uri.String()) {
				return nil
			}
		}
	}

	return errNoSANMatch
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
