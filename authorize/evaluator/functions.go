package evaluator

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/crypto/cryptobyte"
	cb_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/policy/input"
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
	ca, crl string, certInfo input.ClientCertificateInfo, constraints ClientCertConstraints,
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
		log.Debug().Err(verifyErr).Msg("client certificate failed verification: %w")
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
	// If a SubjectAltName extension is:
	//  - marked as critical, and
	//  - contains only name types that are not recognized by the Go standard
	//    library (i.e. no DNS, email address, IP address, or URI names)
	// then the Go parsing code will add it to the UnhandleCriticalExtensions
	// field of the Certificate struct. This will fail the Verify() call below.
	// Because we support other SAN matching checks, let's avoid this behavior.
	cert.UnhandledCriticalExtensions = slices.DeleteFunc(cert.UnhandledCriticalExtensions,
		func(oid asn1.ObjectIdentifier) bool { return oid.Equal(oidSubjectAltName) })

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

	// Consult CRLs only for the first CA in the chain, to match Envoy's
	// behavior when the only_verify_leaf_cert_crl option is set (see
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto).
	if len(chain) < 2 {
		return nil
	}
	cert, issuer := chain[0], chain[1]
	crl := crls[string(issuer.RawSubject)]
	if crl == nil {
		return nil
	}

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
	if r := matchers[config.SANTypeUserPrincipalName]; r != nil {
		names, err := getUserPrincipalNamesFromCert(cert)
		if err != nil {
			return err
		}
		for _, name := range names {
			if r.MatchString(name) {
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

var (
	oidSubjectAltName    = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidUserPrincipalName = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	otherNameTag         = cb_asn1.Tag(0).Constructed().ContextSpecific()
	otherNameValueTag    = cb_asn1.Tag(0).Constructed().ContextSpecific()
)

func getUserPrincipalNamesFromSAN(raw []byte) ([]string, error) {
	san := cryptobyte.String(raw)
	var generalNames cryptobyte.String
	if !san.ReadASN1(&generalNames, cb_asn1.SEQUENCE) {
		return nil, errors.New("error reading GeneralNames sequence")
	}
	var upns []string
	for !generalNames.Empty() {
		var name cryptobyte.String
		var tag cb_asn1.Tag
		if !generalNames.ReadAnyASN1(&name, &tag) {
			return nil, errors.New("error reading GeneralName")
		} else if tag != otherNameTag {
			continue
		}

		var oid asn1.ObjectIdentifier
		if !name.ReadASN1ObjectIdentifier(&oid) {
			return nil, errors.New("error reading OtherName type ID")
		} else if !oid.Equal(oidUserPrincipalName) {
			continue
		}

		var value cryptobyte.String
		if !name.ReadASN1(&value, otherNameValueTag) {
			return nil, errors.New("error reading UserPrincipalName value")
		}

		var utf8string cryptobyte.String
		if !value.ReadASN1(&utf8string, cb_asn1.UTF8String) {
			return nil, errors.New("error reading UserPrincipalName: expected UTF8String")
		}
		upns = append(upns, string(utf8string))
	}
	return upns, nil
}

func getUserPrincipalNamesFromCert(cert *x509.Certificate) ([]string, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			return getUserPrincipalNamesFromSAN(ext.Value)
		}
	}
	return nil, nil
}
