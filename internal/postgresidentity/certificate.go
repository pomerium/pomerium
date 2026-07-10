// Package postgresidentity owns the client certificate identity contract for
// native PostgreSQL access.
package postgresidentity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	BindingIDPrefix     = "postgrescert-SHA256:"
	DetailRouteHostname = "Postgres Route Hostname"
	maxCertificateLife  = 65 * time.Minute
)

// CertificateIdentity is the validated identity derived from a PostgreSQL
// client certificate.
type CertificateIdentity struct {
	Certificate *x509.Certificate
	BindingID   string
	Fingerprint [sha256.Size]byte
}

// ParseAndValidateCertificatePEM validates the single-certificate profile
// issued by pomerium-cli and derives its session binding identity.
func ParseAndValidateCertificatePEM(data []byte, routeHostname string, now time.Time) (*CertificateIdentity, error) {
	var err error
	routeHostname, err = ValidateRouteHostname(routeHostname)
	if err != nil {
		return nil, err
	}

	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("postgres client certificate PEM is invalid")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("postgres client certificate must contain exactly one certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("postgres client certificate is invalid: %w", err)
	}
	if cert.Version != 3 {
		return nil, errors.New("postgres client certificate must be X.509 version 3")
	}
	if cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 {
		return nil, errors.New("postgres client certificate serial number must be positive")
	}
	if !cert.BasicConstraintsValid || cert.IsCA {
		return nil, errors.New("postgres client certificate must be a non-CA certificate")
	}
	if len(cert.UnhandledCriticalExtensions) != 0 {
		return nil, errors.New("postgres client certificate has unsupported critical extensions")
	}
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		return nil, errors.New("postgres client certificate must only allow digital signatures")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(cert.UnknownExtKeyUsage) != 0 {
		return nil, errors.New("postgres client certificate must only allow client authentication")
	}
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok || cert.PublicKeyAlgorithm != x509.Ed25519 {
		return nil, errors.New("postgres client certificate must use an Ed25519 key")
	}
	if cert.SignatureAlgorithm != x509.PureEd25519 || !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return nil, errors.New("postgres client certificate must be self-signed with Ed25519")
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return nil, fmt.Errorf("postgres client certificate self-signature is invalid: %w", err)
	}
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, errors.New("postgres client certificate is not currently valid")
	}
	if cert.NotAfter.Sub(cert.NotBefore) > maxCertificateLife {
		return nil, errors.New("postgres client certificate validity exceeds 65 minutes")
	}
	certHostname := ""
	if len(cert.DNSNames) == 1 {
		certHostname, _ = ValidateRouteHostname(cert.DNSNames[0])
	}
	if len(cert.DNSNames) != 1 || certHostname != routeHostname ||
		len(cert.EmailAddresses) != 0 || len(cert.IPAddresses) != 0 || len(cert.URIs) != 0 {
		return nil, errors.New("postgres client certificate must contain exactly the route hostname as its DNS SAN")
	}

	fingerprint := sha256.Sum256(cert.Raw)
	return &CertificateIdentity{
		Certificate: cert,
		BindingID:   BindingIDFromFingerprint(fingerprint[:]),
		Fingerprint: fingerprint,
	}, nil
}

// BindingIDFromFingerprint encodes a SHA-256 certificate fingerprint in the
// native PostgreSQL SessionBinding key format.
func BindingIDFromFingerprint(fingerprint []byte) string {
	if len(fingerprint) != sha256.Size {
		return ""
	}
	return BindingIDPrefix + base64.RawStdEncoding.EncodeToString(fingerprint)
}

// CanonicalHostname returns the single representation used for PostgreSQL
// route lookup, certificate SANs, and session-binding scope.
func CanonicalHostname(hostname string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
}

// ValidateRouteHostname validates an exact DNS name suitable for PostgreSQL
// SNI routing and returns its canonical representation.
func ValidateRouteHostname(hostname string) (string, error) {
	if hostname == "" || hostname != strings.TrimSpace(hostname) || strings.HasSuffix(hostname, "..") {
		return "", errors.New("postgres route hostname is invalid")
	}
	canonical := CanonicalHostname(hostname)
	if canonical == "" || len(canonical) > 253 || net.ParseIP(canonical) != nil || strings.Contains(canonical, "*") {
		return "", errors.New("postgres route hostname is invalid")
	}
	for _, label := range strings.Split(canonical, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("postgres route hostname is invalid")
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", errors.New("postgres route hostname is invalid")
			}
		}
	}
	return canonical, nil
}
