package controlplane

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	envoy_admin_v3 "github.com/envoyproxy/go-control-plane/envoy/admin/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_data_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/protoutil"
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

func TestDynamicAccessLogFields(t *testing.T) {
	entry := &envoy_data_accesslog_v3.HTTPAccessLogEntry{
		CommonProperties: &envoy_data_accesslog_v3.AccessLogCommon{
			SampleRate: rand.Float64(),
			StartTime:  timestamppb.Now(),
			ResponseFlags: &envoy_data_accesslog_v3.ResponseFlags{
				FailedLocalHealthcheck: true,
			},
			DownstreamDirectRemoteAddress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: envoy_config_core_v3.SocketAddress_TCP,
						Address:  "1.2.3.4",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: rand.Uint32(),
						},
					},
				},
			},
			TlsProperties: &envoy_data_accesslog_v3.TLSProperties{
				TlsSessionId:   "example-session-id",
				Ja3Fingerprint: "example-ja3-fingerprint",
			},
			Metadata: &envoy_config_core_v3.Metadata{
				TypedFilterMetadata: map[string]*anypb.Any{
					"key1": protoutil.NewAnyBool(true),
					"key2": protoutil.NewAnyString("value"),
					"key3": protoutil.NewAnyInt32(42),
					"Any": protoutil.NewAny(&envoy_admin_v3.ClustersConfigDump_DynamicCluster{
						Cluster: protoutil.NewAnyInt32(1234),
					}),
				},
			},
			RouteName: "route-name",
			FilterStateObjects: map[string]*anypb.Any{
				"msg1": protoutil.NewAny(&envoy_config_core_v3.Address{
					Address: &envoy_config_core_v3.Address_EnvoyInternalAddress{
						EnvoyInternalAddress: &envoy_config_core_v3.EnvoyInternalAddress{
							AddressNameSpecifier: &envoy_config_core_v3.EnvoyInternalAddress_ServerListenerName{
								ServerListenerName: "sample-server-listener-name",
							},
							EndpointId: "sample-endpoint-id",
						},
					},
				}),
			},
			CustomTags: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			Duration:                     durationpb.New(time.Duration(rand.Uint32())),
			UpstreamRequestAttemptCount:  rand.Uint32(),
			ConnectionTerminationDetails: "details",
			StreamId:                     "example-stream-id",
			IntermediateLogEntry:         true,
			AccessLogType:                envoy_data_accesslog_v3.AccessLogType_DownstreamStart,
		},
		ProtocolVersion: envoy_data_accesslog_v3.HTTPAccessLogEntry_HTTP11,
		Response: &envoy_data_accesslog_v3.HTTPResponseProperties{
			ResponseHeaders: map[string]string{
				"responseHeader1": "responseHeaderValue1",
				"responseHeader2": "responseHeaderValue2",
			},
			ResponseTrailers: map[string]string{
				"responseTrailer1": "responseTrailerValue1",
				"responseTrailer2": "responseTrailerValue2",
			},
			ResponseHeadersBytes: rand.Uint64(),
		},
	}

	cases := []struct {
		field  string
		expect any
	}{
		{"test%d=.common_properties.sample_rate", entry.CommonProperties.SampleRate},
		{"test%d=.common_properties.start_time", entry.CommonProperties.StartTime},
		{"test%d=.common_properties.response_flags.failed_local_healthcheck", entry.CommonProperties.ResponseFlags.FailedLocalHealthcheck},
		{"test%d=.common_properties.upstream_remote_address", json.RawMessage("{}")},                        // unset
		{"test%d=.common_properties.upstream_remote_address.socket_address.address", json.RawMessage(`""`)}, // parent message unset
		{"test%d=.common_properties.downstream_direct_remote_address.socket_address.address", entry.CommonProperties.DownstreamDirectRemoteAddress.GetSocketAddress().GetAddress()},
		{"test%d=.common_properties.tls_properties.tls_session_id", entry.CommonProperties.TlsProperties.TlsSessionId},
		{"test%d=.common_properties.tls_properties.ja3_fingerprint", entry.CommonProperties.TlsProperties.Ja3Fingerprint},
		{`test%d=.common_properties.metadata.typed_filter_metadata["key1"].(google.protobuf.BoolValue)`, true},
		{`test%d=.common_properties.metadata.typed_filter_metadata["key2"].(google.protobuf.StringValue)`, "value"},
		{`test%d=.common_properties.metadata.typed_filter_metadata["key3"].(google.protobuf.Int32Value)`, int32(42)},
		{`test%d=.common_properties.metadata.typed_filter_metadata["Any"]`, entry.CommonProperties.Metadata.TypedFilterMetadata["Any"]},
		{`test%d=.common_properties.metadata.typed_filter_metadata["Any"].(envoy.admin.v3.ClustersConfigDump.DynamicCluster).cluster.(google.protobuf.Int32Value)`, int32(1234)},
		{"test%d=.common_properties.route_name", entry.CommonProperties.RouteName},
		{`test%d=.common_properties.filter_state_objects["msg1"]`, entry.CommonProperties.FilterStateObjects["msg1"]},
		{`test%d=.common_properties.custom_tags["key1"]`, "value1"},
		{`test%d=.common_properties.custom_tags["key2"]`, "value2"},
		{`test%d=.common_properties.custom_tags["key3"]`, json.RawMessage("null")}, // missing key
		{`test%d=.common_properties.custom_tags["key3"].nonexistent`, "<error: attempting to access field 'nonexistent' of non-message type>"},
		{`test%d=.common_properties.duration`, entry.CommonProperties.Duration},
		{`test%d=.common_properties.upstream_request_attempt_count`, entry.CommonProperties.UpstreamRequestAttemptCount},
		{`test%d=.common_properties.connection_termination_details`, entry.CommonProperties.ConnectionTerminationDetails},
		{`test%d=.common_properties.stream_id`, entry.CommonProperties.StreamId},
		{`test%d=.common_properties.intermediate_log_entry`, entry.CommonProperties.IntermediateLogEntry},
		{`test%d=.common_properties.access_log_type`, entry.CommonProperties.AccessLogType},
		{`test%d=.response.response_headers["responseHeader1"]`, "responseHeaderValue1"},
		{`test%d=.response.response_headers["responseHeader2"]`, "responseHeaderValue2"},
		{`test%d=.response.response_trailers["responseTrailer1"]`, "responseTrailerValue1"},
		{`test%d=.response.response_trailers["responseTrailer2"]`, "responseTrailerValue2"},
		{`test%d=.response.response_headers_bytes`, entry.Response.ResponseHeadersBytes},
		{`test%d=.common_properties.filter_state_objects["msg1"].(envoy.config.core.v3.Address).envoy_internal_address.server_listener_name`, "sample-server-listener-name"},
	}

	for i, tc := range cases {
		field := fmt.Sprintf(string(tc.field), i)
		t.Run(field, func(t *testing.T) {
			t.Parallel()

			var expectedJson string
			switch tc.expect.(type) {
			case string:
				expectedJson = fmt.Sprintf(`{"test%d":"%s"}`, i, tc.expect)
			case json.RawMessage:
				expectedJson = fmt.Sprintf(`{"test%d":%s}`, i, string(tc.expect.(json.RawMessage)))
			case proto.Message:
				msgJson, err := protojson.Marshal(tc.expect.(proto.Message))
				require.NoError(t, err)
				expectedJson = fmt.Sprintf(`{"test%d":%s}`, i, string(msgJson))
			case protoreflect.Enum:
				expectedJson = fmt.Sprintf(`{"test%d":"%v"}`, i, tc.expect)
			default:
				expectedJson = fmt.Sprintf(`{"test%d":%v}`, i, tc.expect)
			}
			var buf bytes.Buffer
			lg := zerolog.New(&buf)
			evt := lg.Log()
			evt = populateLogEvent(log.AccessLogField(field), evt, entry)
			evt.Send()

			assert.Equal(t, expectedJson, strings.TrimSpace(buf.String()))
		})
	}
}
