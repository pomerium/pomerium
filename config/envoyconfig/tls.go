package envoyconfig

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
)

var (
	tlsDownstreamParams = &envoy_extensions_transport_sockets_tls_v3.TlsParameters{
		CipherSuites: []string{
			"ECDHE-ECDSA-AES256-GCM-SHA384",
			"ECDHE-RSA-AES256-GCM-SHA384",
			"ECDHE-ECDSA-AES128-GCM-SHA256",
			"ECDHE-RSA-AES128-GCM-SHA256",
			"ECDHE-ECDSA-CHACHA20-POLY1305",
			"ECDHE-RSA-CHACHA20-POLY1305",
		},
		TlsMinimumProtocolVersion: envoy_extensions_transport_sockets_tls_v3.TlsParameters_TLSv1_2,
		TlsMaximumProtocolVersion: envoy_extensions_transport_sockets_tls_v3.TlsParameters_TLSv1_3,
	}
	tlsUpstreamParams = &envoy_extensions_transport_sockets_tls_v3.TlsParameters{
		CipherSuites: []string{
			"ECDHE-ECDSA-AES256-GCM-SHA384",
			"ECDHE-RSA-AES256-GCM-SHA384",
			"ECDHE-ECDSA-AES128-GCM-SHA256",
			"ECDHE-RSA-AES128-GCM-SHA256",
			"ECDHE-ECDSA-CHACHA20-POLY1305",
			"ECDHE-RSA-CHACHA20-POLY1305",
			"ECDHE-ECDSA-AES128-SHA",
			"ECDHE-RSA-AES128-SHA",
			"AES128-GCM-SHA256",
			"AES128-SHA",
			"ECDHE-ECDSA-AES256-SHA",
			"ECDHE-RSA-AES256-SHA",
			"AES256-GCM-SHA384",
			"AES256-SHA",
		},
		EcdhCurves: []string{
			"X25519",
			"P-256",
			"P-384",
			"P-521",
		},
		TlsMinimumProtocolVersion: envoy_extensions_transport_sockets_tls_v3.TlsParameters_TLSv1_2,
		TlsMaximumProtocolVersion: envoy_extensions_transport_sockets_tls_v3.TlsParameters_TLSv1_3,
	}
	tlsParamsEdDSAOnly = &envoy_extensions_transport_sockets_tls_v3.TlsParameters{
		SignatureAlgorithms:       []string{"ed25519"},
		TlsMinimumProtocolVersion: envoy_extensions_transport_sockets_tls_v3.TlsParameters_TLSv1_3,
		TlsMaximumProtocolVersion: envoy_extensions_transport_sockets_tls_v3.TlsParameters_TLSv1_3,
	}
)

var oidMustStaple = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}

func (b *Builder) buildSubjectAltNameMatcher(
	dst *url.URL,
	overrideName string,
) *envoy_extensions_transport_sockets_tls_v3.SubjectAltNameMatcher {
	sni := dst.Hostname()
	if overrideName != "" {
		sni = overrideName
	}

	if ip, err := netip.ParseAddr(sni); err == nil {
		// Strip off any IPv6 zone.
		if ip.Zone() != "" {
			ip = ip.WithZone("")
		}
		return &envoy_extensions_transport_sockets_tls_v3.SubjectAltNameMatcher{
			SanType: envoy_extensions_transport_sockets_tls_v3.SubjectAltNameMatcher_IP_ADDRESS,
			Matcher: &envoy_type_matcher_v3.StringMatcher{
				MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
					Exact: ip.String(),
				},
			},
		}
	}

	if strings.Contains(sni, "*") {
		pattern := regexp.QuoteMeta(sni)
		pattern = strings.Replace(pattern, "\\*", ".*", -1)
		return &envoy_extensions_transport_sockets_tls_v3.SubjectAltNameMatcher{
			SanType: envoy_extensions_transport_sockets_tls_v3.SubjectAltNameMatcher_DNS,
			Matcher: &envoy_type_matcher_v3.StringMatcher{
				MatchPattern: &envoy_type_matcher_v3.StringMatcher_SafeRegex{
					SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
						EngineType: &envoy_type_matcher_v3.RegexMatcher_GoogleRe2{
							GoogleRe2: &envoy_type_matcher_v3.RegexMatcher_GoogleRE2{},
						},
						Regex: pattern,
					},
				},
			},
		}
	}

	return &envoy_extensions_transport_sockets_tls_v3.SubjectAltNameMatcher{
		SanType: envoy_extensions_transport_sockets_tls_v3.SubjectAltNameMatcher_DNS,
		Matcher: &envoy_type_matcher_v3.StringMatcher{
			MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
				Exact: sni,
			},
		},
	}
}

func (b *Builder) buildSubjectNameIndication(
	dst *url.URL,
	overrideName string,
) string {
	sni := dst.Hostname()
	if overrideName != "" {
		sni = overrideName
	}
	sni = strings.Replace(sni, "*", "example", -1)
	return sni
}

// validateCertificate validates that a certificate can be used with Envoy's TLS stack.
func validateCertificate(cert *tls.Certificate) error {
	if len(cert.Certificate) == 0 {
		return nil
	}

	// parse the x509 certificate because leaf isn't always filled in
	x509cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}

	// check to make sure that if we require an OCSP staple that its available.
	if len(cert.OCSPStaple) == 0 && hasMustStaple(x509cert) {
		return fmt.Errorf("certificate requires OCSP stapling but has no OCSP staple response")
	}

	return nil
}

func hasMustStaple(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidMustStaple) {
			return true
		}
	}
	return false
}
