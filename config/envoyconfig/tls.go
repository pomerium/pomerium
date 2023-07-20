package envoyconfig

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
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

	if net.ParseIP(sni) != nil {
		return &envoy_extensions_transport_sockets_tls_v3.SubjectAltNameMatcher{
			SanType: envoy_extensions_transport_sockets_tls_v3.SubjectAltNameMatcher_IP_ADDRESS,
			Matcher: &envoy_type_matcher_v3.StringMatcher{
				MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
					Exact: sni,
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
