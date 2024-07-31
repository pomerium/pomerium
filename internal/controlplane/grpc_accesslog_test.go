package controlplane

import (
	"bytes"
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
			TimeToLastDownstreamTxByte: durationpb.New(time.Second * 3),
			UpstreamCluster:            "UPSTREAM-CLUSTER",
		},
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
	httpEntry := &envoy_data_accesslog_v3.HTTPAccessLogEntry{
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
				PeerCertificateProperties: &envoy_data_accesslog_v3.TLSProperties_CertificateProperties{
					SubjectAltName: []*envoy_data_accesslog_v3.TLSProperties_CertificateProperties_SubjectAltName{
						{San: &envoy_data_accesslog_v3.TLSProperties_CertificateProperties_SubjectAltName_Dns{Dns: "foo"}},
						{San: &envoy_data_accesslog_v3.TLSProperties_CertificateProperties_SubjectAltName_Uri{Uri: "bar"}},
					},
				},
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
	tcpEntry := &envoy_data_accesslog_v3.TCPAccessLogEntry{
		CommonProperties: httpEntry.CommonProperties,
		ConnectionProperties: &envoy_data_accesslog_v3.ConnectionProperties{
			ReceivedBytes: 1234,
		},
	}

	cases := []struct {
		field  string
		expect any
	}{
		{"test%d=.common_properties.sample_rate", httpEntry.CommonProperties.SampleRate},
		{"test%d=.common_properties.start_time", httpEntry.CommonProperties.StartTime},
		{"test%d=.common_properties.response_flags.failed_local_healthcheck", httpEntry.CommonProperties.ResponseFlags.FailedLocalHealthcheck},
		{"test%d=.common_properties.upstream_remote_address", json.RawMessage("{}")},      // unset
		{"test%d=.common_properties.upstream_remote_address.socket_address.address", nil}, // parent message unset
		{"test%d=.common_properties.downstream_direct_remote_address.socket_address.address", httpEntry.CommonProperties.DownstreamDirectRemoteAddress.GetSocketAddress().GetAddress()},
		{"test%d=.common_properties.tls_properties.tls_session_id", httpEntry.CommonProperties.TlsProperties.TlsSessionId},
		{"test%d=.common_properties.tls_properties.ja3_fingerprint", httpEntry.CommonProperties.TlsProperties.Ja3Fingerprint},
		{"test%d=.common_properties.tls_properties.peer_certificate_properties.subject_alt_name[0].dns", "foo"},
		{"test%d=.common_properties.tls_properties.peer_certificate_properties.subject_alt_name[1].uri", "bar"},
		{"test%d=.common_properties.tls_properties.peer_certificate_properties.subject_alt_name", json.RawMessage(`[{"dns":"foo"},{"uri":"bar"}]`)},
		{`test%d=.common_properties.metadata.typed_filter_metadata["key1"].(google.protobuf.BoolValue)`, true},
		{`test%d=.common_properties.metadata.typed_filter_metadata["key2"].(google.protobuf.StringValue)`, "value"},
		{`test%d=.common_properties.metadata.typed_filter_metadata["key3"].(google.protobuf.Int32Value)`, int32(42)},
		{`test%d=.common_properties.metadata.typed_filter_metadata["Any"]`, httpEntry.CommonProperties.Metadata.TypedFilterMetadata["Any"]},
		{`test%d=.common_properties.metadata.typed_filter_metadata["Any"].(envoy.admin.v3.ClustersConfigDump.DynamicCluster).cluster.(google.protobuf.Int32Value)`, int32(1234)},
		{"test%d=.common_properties.route_name", httpEntry.CommonProperties.RouteName},
		{`test%d=.common_properties.filter_state_objects["msg1"]`, httpEntry.CommonProperties.FilterStateObjects["msg1"]},
		{`test%d=.common_properties.custom_tags["key1"]`, "value1"},
		{`test%d=.common_properties.custom_tags["key2"]`, "value2"},
		{`test%d=.common_properties.custom_tags`, json.RawMessage(`{"key1":"value1","key2":"value2"}`)},
		{`test%d=.common_properties.custom_tags["key3"]`, nil}, // missing key
		{`test%d=.common_properties.custom_tags["key3"].nonexistent`, "<error: cannot access field 'nonexistent' of non-message type>"},
		{`test%d=.common_properties.duration`, httpEntry.CommonProperties.Duration},
		{`test%d=.common_properties.upstream_request_attempt_count`, httpEntry.CommonProperties.UpstreamRequestAttemptCount},
		{`test%d=.common_properties.connection_termination_details`, httpEntry.CommonProperties.ConnectionTerminationDetails},
		{`test%d=.common_properties.stream_id`, httpEntry.CommonProperties.StreamId},
		{`test%d=.common_properties.intermediate_log_entry`, httpEntry.CommonProperties.IntermediateLogEntry},
		{`test%d=.common_properties.access_log_type`, httpEntry.CommonProperties.AccessLogType},
		{`test%d=.response.response_headers["responseHeader1"]`, "responseHeaderValue1"},
		{`test%d=.response.response_headers["responseHeader2"]`, "responseHeaderValue2"},
		{`test%d=.response.response_trailers["responseTrailer1"]`, "responseTrailerValue1"},
		{`test%d=.response.response_trailers["responseTrailer2"]`, "responseTrailerValue2"},
		{`test%d=.response.response_headers_bytes`, httpEntry.Response.ResponseHeadersBytes},
		{`test%d=.common_properties.filter_state_objects["msg1"].(envoy.config.core.v3.Address).envoy_internal_address.server_listener_name`, "sample-server-listener-name"},
		{`test%d=.connection_properties.received_bytes`, 1234},

		{`test%d=.common_properties.metadata.typed_filter_metadata`, json.RawMessage(
			`{"Any":{"@type":"type.googleapis.com/envoy.admin.v3.ClustersConfigDump.DynamicCluster","cluster":{"@type":"type.googleapis.com/google.protobuf.Int32Value","value":1234}},` +
				`"key1":{"@type":"type.googleapis.com/google.protobuf.BoolValue","value":true},` +
				`"key2":{"@type":"type.googleapis.com/google.protobuf.StringValue","value":"value"},` +
				`"key3":{"@type":"type.googleapis.com/google.protobuf.Int32Value","value":42}}`)},
	}

	for i, tc := range cases {
		field := fmt.Sprintf(tc.field, i)
		t.Run(field, func(t *testing.T) {
			t.Parallel()

			var expected string
			switch tc.expect.(type) {
			case string:
				expected = fmt.Sprintf(`{"test%d":"%s"}`, i, tc.expect)
			case json.RawMessage:
				expected = fmt.Sprintf(`{"test%d":%s}`, i, string(tc.expect.(json.RawMessage)))
			case proto.Message:
				msg, err := protojson.Marshal(tc.expect.(proto.Message))
				require.NoError(t, err)
				expected = fmt.Sprintf(`{"test%d":%s}`, i, string(msg))
			case protoreflect.Enum:
				expected = fmt.Sprintf(`{"test%d":"%v"}`, i, tc.expect)
			case nil:
				expected = "{}"
			default:
				expected = fmt.Sprintf(`{"test%d":%v}`, i, tc.expect)
			}

			var httpOnly, tcpOnly bool
			switch {
			case strings.HasPrefix(tc.field, "test%d=.request"):
				httpOnly = true
			case strings.HasPrefix(tc.field, "test%d=.response"):
				httpOnly = true
			case strings.HasPrefix(tc.field, "test%d=.protocol_version"):
				httpOnly = true
			case strings.HasPrefix(tc.field, "test%d=.connection_properties"):
				tcpOnly = true
			}

			{
				var buf bytes.Buffer
				lg := zerolog.New(&buf)
				evt := lg.Log()
				evt = populateLogEvent(log.AccessLogField(field), evt, httpEntry)
				evt.Send()

				if !tcpOnly {
					assert.Equal(t, expected, strings.TrimSpace(buf.String()))
				} else {
					assert.Equal(t, "{}", strings.TrimSpace(buf.String()))
				}
			}

			{
				var buf bytes.Buffer
				lg := zerolog.New(&buf)
				evt := lg.Log()
				evt = populateLogEvent(log.AccessLogField(field), evt, tcpEntry)
				evt.Send()

				if !httpOnly {
					assert.Equal(t, expected, strings.TrimSpace(buf.String()))
				} else {
					assert.Equal(t, "{}", strings.TrimSpace(buf.String()))
				}
			}
		})
	}
}
