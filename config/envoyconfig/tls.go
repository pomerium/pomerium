package envoyconfig

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
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

func (b *Builder) envoyTLSCertificateFromGoTLSCertificate(
	ctx context.Context,
	cert *tls.Certificate,
) *envoy_extensions_transport_sockets_tls_v3.TlsCertificate {
	envoyCert := &envoy_extensions_transport_sockets_tls_v3.TlsCertificate{}
	var chain bytes.Buffer
	for _, cbs := range cert.Certificate {
		_ = pem.Encode(&chain, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cbs,
		})
	}
	envoyCert.CertificateChain = b.filemgr.BytesDataSource("tls-crt.pem", chain.Bytes())
	if cert.OCSPStaple != nil {
		envoyCert.OcspStaple = b.filemgr.BytesDataSource("ocsp-staple", cert.OCSPStaple)
	}
	if bs, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey); err == nil {
		envoyCert.PrivateKey = b.filemgr.BytesDataSource("tls-key.pem", pem.EncodeToMemory(
			&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: bs,
			},
		))
	} else {
		log.Ctx(ctx).Error().Err(err).Msg("failed to marshal private key for tls config")
	}
	for _, scts := range cert.SignedCertificateTimestamps {
		envoyCert.SignedCertificateTimestamp = append(envoyCert.SignedCertificateTimestamp,
			b.filemgr.BytesDataSource("signed-certificate-timestamp", scts))
	}
	return envoyCert
}

func (b *Builder) envoyTLSCertificatesFromGoTLSCertificates(ctx context.Context, certs []tls.Certificate) (
	[]*envoy_extensions_transport_sockets_tls_v3.TlsCertificate, error,
) {
	envoyCerts := make([]*envoy_extensions_transport_sockets_tls_v3.TlsCertificate, 0, len(certs))
	for i := range certs {
		cert := &certs[i]
		if err := validateCertificate(cert); err != nil {
			return nil, fmt.Errorf("invalid certificate for domain %s: %w",
				cert.Leaf.Subject.CommonName, err)
		}
		envoyCert := b.envoyTLSCertificateFromGoTLSCertificate(ctx, cert)
		envoyCerts = append(envoyCerts, envoyCert)
	}
	return envoyCerts, nil
}

// clientCABundle returns a bundle of the globally configured client CA and any
// per-route client CAs.
func clientCABundle(ctx context.Context, cfg *config.Config) []byte {
	var bundle bytes.Buffer
	ca, _ := cfg.Options.DownstreamMTLS.GetCA()
	addCAToBundle(&bundle, ca)
	for p := range cfg.Options.GetAllPolicies() {
		// We don't need to check TLSDownstreamClientCAFile here because
		// Policy.Validate() will populate TLSDownstreamClientCA when
		// TLSDownstreamClientCAFile is set.
		if p.TLSDownstreamClientCA == "" {
			continue
		}
		ca, err := base64.StdEncoding.DecodeString(p.TLSDownstreamClientCA)
		if err != nil {
			log.Ctx(ctx).Error().Stringer("policy", p).Err(err).Msg("invalid client CA")
			continue
		}
		addCAToBundle(&bundle, ca)
	}
	return bundle.Bytes()
}

func addCAToBundle(bundle *bytes.Buffer, ca []byte) {
	if len(ca) == 0 {
		return
	}
	bundle.Write(ca)
	// Make sure each CA is separated by a newline.
	if ca[len(ca)-1] != '\n' {
		bundle.WriteByte('\n')
	}
}

func getAllCertificates(cfg *config.Config) ([]tls.Certificate, error) {
	allCertificates, err := cfg.AllCertificates()
	if err != nil {
		return nil, fmt.Errorf("error collecting all certificates: %w", err)
	}

	wc, err := cfg.GenerateCatchAllCertificate()
	if err != nil {
		return nil, fmt.Errorf("error getting wildcard certificate: %w", err)
	}

	return append(allCertificates, *wc), nil
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

func newDownstreamTLSTransportSocket(
	downstreamTLSContext *envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext,
) *envoy_config_core_v3.TransportSocket {
	return &envoy_config_core_v3.TransportSocket{
		Name: "tls",
		ConfigType: &envoy_config_core_v3.TransportSocket_TypedConfig{
			TypedConfig: marshalAny(downstreamTLSContext),
		},
	}
}

func (b *Builder) buildDownstreamTLSContextMulti(
	ctx context.Context,
	cfg *config.Config,
	certs []tls.Certificate,
) (
	*envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext,
	error,
) {
	envoyCerts, err := b.envoyTLSCertificatesFromGoTLSCertificates(ctx, certs)
	if err != nil {
		return nil, err
	}
	dtc := &envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext{
		CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
			TlsParams:       tlsDownstreamParams,
			TlsCertificates: envoyCerts,
			AlpnProtocols:   getALPNProtos(cfg.Options),
		},
	}
	b.buildDownstreamValidationContext(ctx, dtc, cfg)
	return dtc, nil
}

func getALPNProtos(opts *config.Options) []string {
	switch opts.GetCodecType() {
	case config.CodecTypeHTTP1:
		return []string{"http/1.1"}
	case config.CodecTypeHTTP2:
		return []string{"h2"}
	default:
		return []string{"h2", "http/1.1"}
	}
}

func (b *Builder) buildDownstreamValidationContext(
	ctx context.Context,
	dtc *envoy_extensions_transport_sockets_tls_v3.DownstreamTlsContext,
	cfg *config.Config,
) {
	clientCA := clientCABundle(ctx, cfg)
	if len(clientCA) == 0 {
		return
	}

	vc := &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
		TrustedCa: b.filemgr.BytesDataSource("client-ca.pem", clientCA),
		MatchTypedSubjectAltNames: make([]*envoy_extensions_transport_sockets_tls_v3.SubjectAltNameMatcher,
			0, len(cfg.Options.DownstreamMTLS.MatchSubjectAltNames)),
		OnlyVerifyLeafCertCrl: true,
	}
	for i := range cfg.Options.DownstreamMTLS.MatchSubjectAltNames {
		vc.MatchTypedSubjectAltNames = append(vc.MatchTypedSubjectAltNames,
			cfg.Options.DownstreamMTLS.MatchSubjectAltNames[i].ToEnvoyProto())
	}

	if d := cfg.Options.DownstreamMTLS.GetMaxVerifyDepth(); d > 0 {
		vc.MaxVerifyDepth = wrapperspb.UInt32(d)
	}

	if cfg.Options.DownstreamMTLS.GetEnforcement() == config.MTLSEnforcementRejectConnection {
		dtc.RequireClientCertificate = wrapperspb.Bool(true)
	} else {
		vc.TrustChainVerification = envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext_ACCEPT_UNTRUSTED
	}

	if crl := cfg.Options.DownstreamMTLS.CRL; crl != "" {
		bs, err := base64.StdEncoding.DecodeString(crl)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("invalid client CRL")
		} else {
			vc.Crl = b.filemgr.BytesDataSource("client-crl.pem", bs)
		}
	} else if crlf := cfg.Options.DownstreamMTLS.CRLFile; crlf != "" {
		vc.Crl = b.filemgr.FileDataSource(crlf)
	}

	dtc.CommonTlsContext.ValidationContextType = &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext{
		ValidationContext: vc,
	}
}
