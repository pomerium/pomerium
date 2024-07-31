package controlplane

import (
	"bytes"
	"crypto/tls"
	"strings"
	"testing"
	"time"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_data_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/internal/log"
)

func Test_populateLogEvent(t *testing.T) {
	t.Parallel()

	entry := &envoy_data_accesslog_v3.HTTPAccessLogEntry{
		CommonProperties: &envoy_data_accesslog_v3.AccessLogCommon{
			DownstreamRemoteAddress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Address: "127.0.0.1",
					},
				},
			},
			DownstreamLocalAddress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: envoy_config_core_v3.SocketAddress_TCP,
						Address:  "10.10.10.10",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: 12345,
						},
					},
				},
			},
			TlsProperties: &envoy_data_accesslog_v3.TLSProperties{
				TlsVersion:     envoy_data_accesslog_v3.TLSProperties_TLSv1_3,
				TlsCipherSuite: wrapperspb.UInt32(uint32(tls.TLS_AES_256_GCM_SHA384)),
				TlsSniHostname: "www.example.com",
				LocalCertificateProperties: &envoy_data_accesslog_v3.TLSProperties_CertificateProperties{
					Subject: "local-example-subject",
					Issuer:  "local-example-issuer",
					SubjectAltName: []*envoy_data_accesslog_v3.TLSProperties_CertificateProperties_SubjectAltName{
						{San: &envoy_data_accesslog_v3.TLSProperties_CertificateProperties_SubjectAltName_Dns{Dns: "local.example.dns.san1"}},
						{San: &envoy_data_accesslog_v3.TLSProperties_CertificateProperties_SubjectAltName_Dns{Dns: "local.example.dns.san2"}},
						{San: &envoy_data_accesslog_v3.TLSProperties_CertificateProperties_SubjectAltName_Uri{Uri: "local.example.uri.san1"}},
						{San: &envoy_data_accesslog_v3.TLSProperties_CertificateProperties_SubjectAltName_Uri{Uri: "local.example.uri.san2"}},
					},
				},
				PeerCertificateProperties: &envoy_data_accesslog_v3.TLSProperties_CertificateProperties{
					Subject: "peer-example-subject",
					Issuer:  "peer-example-issuer",
					SubjectAltName: []*envoy_data_accesslog_v3.TLSProperties_CertificateProperties_SubjectAltName{
						{San: &envoy_data_accesslog_v3.TLSProperties_CertificateProperties_SubjectAltName_Dns{Dns: "peer.example.dns.san1"}},
						{San: &envoy_data_accesslog_v3.TLSProperties_CertificateProperties_SubjectAltName_Dns{Dns: "peer.example.dns.san2"}},
						{San: &envoy_data_accesslog_v3.TLSProperties_CertificateProperties_SubjectAltName_Uri{Uri: "peer.example.uri.san1"}},
						{San: &envoy_data_accesslog_v3.TLSProperties_CertificateProperties_SubjectAltName_Uri{Uri: "peer.example.uri.san2"}},
					},
				},
			},
			TimeToLastDownstreamTxByte:       durationpb.New(time.Second * 3),
			UpstreamCluster:                  "UPSTREAM-CLUSTER",
			UpstreamTransportFailureReason:   "example-upstream-transport-failure-reason",
			DownstreamTransportFailureReason: "example-downstream-transport-failure-reason",
		},
		ProtocolVersion: envoy_data_accesslog_v3.HTTPAccessLogEntry_HTTP11,
		Request: &envoy_data_accesslog_v3.HTTPRequestProperties{
			Authority:     "AUTHORITY",
			ForwardedFor:  "FORWARDED-FOR",
			Path:          "https://www.example.com/some/path?a=b",
			Referer:       "https://www.example.com/referer?a=b",
			RequestId:     "REQUEST-ID",
			RequestMethod: envoy_config_core_v3.RequestMethod_GET,
			UserAgent:     "USER-AGENT",
		},
		Response: &envoy_data_accesslog_v3.HTTPResponseProperties{
			ResponseBodyBytes:   1234,
			ResponseCode:        wrapperspb.UInt32(200),
			ResponseCodeDetails: "RESPONSE-CODE-DETAILS",
		},
	}

	for _, tc := range []struct {
		field  log.AccessLogField
		expect string
	}{
		{log.AccessLogFieldAuthority, `{"authority":"AUTHORITY"}`},
		{log.AccessLogFieldDuration, `{"duration":3000}`},
		{log.AccessLogFieldForwardedFor, `{"forwarded-for":"FORWARDED-FOR"}`},
		{log.AccessLogFieldIP, `{"ip":"127.0.0.1"}`},
		{log.AccessLogFieldDestIP, `{"dest-ip":"10.10.10.10"}`},
		{log.AccessLogFieldDestPort, `{"dest-port":12345}`},
		{log.AccessLogFieldProtocolVersion, `{"protocol-version":"HTTP11"}`},
		{log.AccessLogFieldMethod, `{"method":"GET"}`},
		{log.AccessLogFieldPath, `{"path":"https://www.example.com/some/path"}`},
		{log.AccessLogFieldQuery, `{"query":"a=b"}`},
		{log.AccessLogFieldReferer, `{"referer":"https://www.example.com/referer"}`},
		{log.AccessLogFieldRequestID, `{"request-id":"REQUEST-ID"}`},
		{log.AccessLogFieldResponseCode, `{"response-code":200}`},
		{log.AccessLogFieldResponseCodeDetails, `{"response-code-details":"RESPONSE-CODE-DETAILS"}`},
		{log.AccessLogFieldSize, `{"size":1234}`},
		{log.AccessLogFieldUpstreamCluster, `{"upstream-cluster":"UPSTREAM-CLUSTER"}`},
		{log.AccessLogFieldUserAgent, `{"user-agent":"USER-AGENT"}`},
		{log.AccessLogFieldUpstreamTransportFailureReason, `{"upstream-transport-failure-reason":"example-upstream-transport-failure-reason"}`},
		{log.AccessLogFieldDownstreamTransportFailureReason, `{"downstream-transport-failure-reason":"example-downstream-transport-failure-reason"}`},
		{log.AccessLogFieldTLSVersion, `{"tls-version":"TLSv1_3"}`},
		{log.AccessLogFieldTLSSNIHostname, `{"tls-sni-hostname":"www.example.com"}`},
		{log.AccessLogFieldTLSCipherSuite, `{"tls-cipher-suite":"TLS_AES_256_GCM_SHA384"}`},
		{log.AccessLogFieldTLSLocalCert, `{"tls-local-cert":{"issuer":"local-example-issuer","subject":"local-example-subject","subjectAltName":["DNS:local.example.dns.san1","DNS:local.example.dns.san2","URI:local.example.uri.san1","URI:local.example.uri.san2"]}}`},
		{log.AccessLogFieldTLSPeerCert, `{"tls-peer-cert":{"issuer":"peer-example-issuer","subject":"peer-example-subject","subjectAltName":["DNS:peer.example.dns.san1","DNS:peer.example.dns.san2","URI:peer.example.uri.san1","URI:peer.example.uri.san2"]}}`},
	} {
		tc := tc
		t.Run(string(tc.field), func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			log := zerolog.New(&buf)
			evt := log.Log()
			evt = populateLogEvent(tc.field, evt, entry)
			evt.Send()

			assert.Equal(t, tc.expect, strings.TrimSpace(buf.String()))
		})
	}
}
