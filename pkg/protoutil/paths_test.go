package protoutil_test

import (
	"crypto/tls"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	envoy_admin_v3 "github.com/envoyproxy/go-control-plane/envoy/admin/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_data_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/data/accesslog/v3"

	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/protoutil/testdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protopath"
	"google.golang.org/protobuf/reflect/protorange"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestParsePath(t *testing.T) {
	entry := &envoy_data_accesslog_v3.HTTPAccessLogEntry{
		CommonProperties: &envoy_data_accesslog_v3.AccessLogCommon{
			SampleRate:                  rand.Float64(),
			StartTime:                   timestamppb.Now(),
			TimeToLastRxByte:            durationpb.New(1),
			TimeToFirstUpstreamTxByte:   durationpb.New(2),
			TimeToLastUpstreamTxByte:    durationpb.New(3),
			TimeToFirstUpstreamRxByte:   durationpb.New(4),
			TimeToLastUpstreamRxByte:    durationpb.New(5),
			TimeToFirstDownstreamTxByte: durationpb.New(6),
			TimeToLastDownstreamTxByte:  durationpb.New(7),
			UpstreamLocalAddress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol:      envoy_config_core_v3.SocketAddress_TCP,
						Address:       "1.2.3.4",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_NamedPort{NamedPort: "foo"},
						ResolverName:  "resolver1",
						Ipv4Compat:    true,
					},
				},
			},
			UpstreamRemoteAddress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol:      envoy_config_core_v3.SocketAddress_TCP,
						Address:       "5.6.7.8",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_NamedPort{NamedPort: "bar"},
						ResolverName:  "resolver2",
						Ipv4Compat:    false,
					},
				},
			},
			ResponseFlags: &envoy_data_accesslog_v3.ResponseFlags{
				FailedLocalHealthcheck:        rand.IntN(2) == 1,
				NoHealthyUpstream:             rand.IntN(2) == 1,
				UpstreamRequestTimeout:        rand.IntN(2) == 1,
				LocalReset:                    rand.IntN(2) == 1,
				UpstreamRemoteReset:           rand.IntN(2) == 1,
				UpstreamConnectionFailure:     rand.IntN(2) == 1,
				UpstreamConnectionTermination: rand.IntN(2) == 1,
				UpstreamOverflow:              rand.IntN(2) == 1,
				NoRouteFound:                  rand.IntN(2) == 1,
				DelayInjected:                 rand.IntN(2) == 1,
				FaultInjected:                 rand.IntN(2) == 1,
				RateLimited:                   rand.IntN(2) == 1,
				UnauthorizedDetails: &envoy_data_accesslog_v3.ResponseFlags_Unauthorized{
					Reason: envoy_data_accesslog_v3.ResponseFlags_Unauthorized_Reason(rand.IntN(2)),
				},
				RateLimitServiceError:            rand.IntN(2) == 1,
				DownstreamConnectionTermination:  rand.IntN(2) == 1,
				UpstreamRetryLimitExceeded:       rand.IntN(2) == 1,
				StreamIdleTimeout:                rand.IntN(2) == 1,
				InvalidEnvoyRequestHeaders:       rand.IntN(2) == 1,
				DownstreamProtocolError:          rand.IntN(2) == 1,
				UpstreamMaxStreamDurationReached: rand.IntN(2) == 1,
				ResponseFromCacheFilter:          rand.IntN(2) == 1,
				NoFilterConfigFound:              rand.IntN(2) == 1,
				DurationTimeout:                  rand.IntN(2) == 1,
				UpstreamProtocolError:            rand.IntN(2) == 1,
				NoClusterFound:                   rand.IntN(2) == 1,
				OverloadManager:                  rand.IntN(2) == 1,
				DnsResolutionFailure:             rand.IntN(2) == 1,
				DownstreamRemoteReset:            rand.IntN(2) == 1,
			},
			DownstreamRemoteAddress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: envoy_config_core_v3.SocketAddress_TCP,
						Address:  "9.10.11.12",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: rand.Uint32(),
						},
					},
				},
			},
			DownstreamDirectRemoteAddress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: envoy_config_core_v3.SocketAddress_TCP,
						Address:  "13.14.15.16",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: rand.Uint32(),
						},
					},
				},
			},
			DownstreamLocalAddress: &envoy_config_core_v3.Address{
				Address: &envoy_config_core_v3.Address_SocketAddress{
					SocketAddress: &envoy_config_core_v3.SocketAddress{
						Protocol: envoy_config_core_v3.SocketAddress_TCP,
						Address:  "17.18.19.20",
						PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
							PortValue: rand.Uint32(),
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
					"map<string, Any>": protoutil.NewAny(&envoy_config_endpoint_v3.ClusterLoadAssignment{
						NamedEndpoints: map[string]*envoy_config_endpoint_v3.Endpoint{
							"key1": {
								Hostname: "value1",
							},
							"key2": {
								AdditionalAddresses: []*envoy_config_endpoint_v3.Endpoint_AdditionalAddress{
									{
										Address: &envoy_config_core_v3.Address{
											Address: &envoy_config_core_v3.Address_SocketAddress{
												SocketAddress: &envoy_config_core_v3.SocketAddress{
													Address: "value2",
												},
											},
										},
									},
								},
							},
						},
					}),
					"repeated Any": protoutil.NewAny(&envoy_admin_v3.ConfigDump{
						Configs: []*anypb.Any{
							protoutil.NewAnyBool(true),
							protoutil.NewAnyString("value"),
							protoutil.NewAnyInt32(42),
							protoutil.NewAny(&envoy_admin_v3.ConfigDump{
								Configs: []*anypb.Any{
									protoutil.NewAnyBool(false),
									protoutil.NewAnyString("value2"),
									protoutil.NewAnyInt32(100),
								},
							}),
						},
					}),
					"nested Any": protoutil.NewAny(protoutil.NewAny(protoutil.NewAnyBool(true))),
					"unusual fields": protoutil.NewAny(&testdata.UnusualFields{
						BoolToAny: map[bool]*anypb.Any{
							true:  protoutil.NewAnyString("true"),
							false: protoutil.NewAnyString("false"),
						},
						Int32ToAny: map[int32]*anypb.Any{
							1:  protoutil.NewAnyString("1"),
							-1: protoutil.NewAnyString("-1"),
						},
						Int64ToAny: map[int64]*anypb.Any{
							1:  protoutil.NewAnyString("1"),
							-1: protoutil.NewAnyString("-1"),
						},
						Uint32ToAny: map[uint32]*anypb.Any{
							1: protoutil.NewAnyString("1"),
							2: protoutil.NewAnyString("2"),
						},
						Uint64ToAny: map[uint64]*anypb.Any{
							1: protoutil.NewAnyString("1"),
							2: protoutil.NewAnyString("2"),
						},
					}),
				},
			},
			RouteName:                        "route-name",
			UpstreamCluster:                  "UPSTREAM-CLUSTER",
			UpstreamTransportFailureReason:   "example-upstream-transport-failure-reason",
			DownstreamTransportFailureReason: "example-downstream-transport-failure-reason",
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
				"msg2": protoutil.NewAny(&envoy_config_core_v3.Address{
					Address: &envoy_config_core_v3.Address_Pipe{
						Pipe: &envoy_config_core_v3.Pipe{
							Path: "sample-pipe-path",
							Mode: rand.Uint32(),
						},
					},
				}),
			},
			CustomTags: map[string]string{
				"key1":                          "value1",
				"key2":                          "value2",
				"][brackets [inside] []string]": "value3",
				"(parentheses (inside)) (string) ())()()(": "value4",
				"\"quotes\" 'inside' \"string'":            "value5",
			},
			Duration:                     durationpb.New(time.Duration(rand.Uint32())),
			UpstreamRequestAttemptCount:  rand.Uint32(),
			ConnectionTerminationDetails: "details",
			StreamId:                     "example-stream-id",
			IntermediateLogEntry:         true,
			DownstreamWireBytesSent:      rand.Uint64(),
			DownstreamWireBytesReceived:  rand.Uint64(),
			UpstreamWireBytesSent:        rand.Uint64(),
			UpstreamWireBytesReceived:    rand.Uint64(),
			AccessLogType:                envoy_data_accesslog_v3.AccessLogType_DownstreamStart,
		},
		ProtocolVersion: envoy_data_accesslog_v3.HTTPAccessLogEntry_HTTP11,
		Request: &envoy_data_accesslog_v3.HTTPRequestProperties{
			Authority:           "AUTHORITY",
			ForwardedFor:        "FORWARDED-FOR",
			Path:                "https://www.example.com/some/path?a=b",
			Referer:             "https://www.example.com/referer?a=b",
			RequestId:           "REQUEST-ID",
			RequestMethod:       envoy_config_core_v3.RequestMethod_GET,
			UserAgent:           "USER-AGENT",
			Scheme:              "https",
			Port:                wrapperspb.UInt32(rand.Uint32()),
			OriginalPath:        "example-original-path",
			RequestHeadersBytes: rand.Uint64(),
			RequestBodyBytes:    rand.Uint64(),
			RequestHeaders: map[string]string{
				"requestHeader1": "requestHeaderValue1",
				"requestHeader2": "requestHeaderValue2",
			},
			UpstreamHeaderBytesSent:       rand.Uint64(),
			DownstreamHeaderBytesReceived: rand.Uint64(),
		},
		Response: &envoy_data_accesslog_v3.HTTPResponseProperties{
			ResponseHeaders: map[string]string{
				"responseHeader1": "responseHeaderValue1",
				"responseHeader2": "responseHeaderValue2",
			},
			ResponseTrailers: map[string]string{
				"responseTrailer1": "responseTrailerValue1",
				"responseTrailer2": "responseTrailerValue2",
			},
			ResponseHeadersBytes:        rand.Uint64(),
			UpstreamHeaderBytesReceived: rand.Uint64(),
			DownstreamHeaderBytesSent:   rand.Uint64(),
			ResponseBodyBytes:           rand.Uint64(),
			ResponseCode:                wrapperspb.UInt32(200),
			ResponseCodeDetails:         "RESPONSE-CODE-DETAILS",
		},
	}

	t.Run("Round Trip", func(t *testing.T) {
		protorange.Range(entry.ProtoReflect(), func(v protopath.Values) error {
			if len(v.Path) == 1 {
				return nil
			}
			pathStr := v.Path[1:].String()
			expectedValue := v.Index(-1).Value

			parsedPath, err := protoutil.ParsePath(entry.ProtoReflect(), pathStr)
			require.NoError(t, err, "path: %s", pathStr)
			assert.Equal(t, v.Path.String(), parsedPath.String())

			actualValue, err := protoutil.DereferencePath(entry, parsedPath)
			require.NoError(t, err)
			assert.True(t, actualValue.Equal(expectedValue),
				"expected %s to equal %s", actualValue, expectedValue)
			return nil
		})
	})

	t.Run("Errors", func(t *testing.T) {
		cases := []struct {
			path string
			err  string
		}{
			{
				path: "",
				err:  "empty path",
			},
			{
				path: "request.route_name",
				err:  "path must start with '.'",
			},
			{
				path: ".request..route_name",
				err:  "path contains empty step",
			},
			{
				path: ".common_properties.route_name[1]",
				err:  "cannot index string field 'envoy.data.accesslog.v3.AccessLogCommon.route_name'",
			},
			{
				path: ".request[1]",
				err:  "cannot index message field 'envoy.data.accesslog.v3.HTTPAccessLogEntry.request'",
			},
			{
				path: ".[1]",
				err:  "cannot index '(envoy.data.accesslog.v3.HTTPAccessLogEntry)'",
			},
			{
				path: `.common_properties.metadata.typed_filter_metadata["repeated Any"].(envoy.admin.v3.ConfigDump).configs[0][0]`,
				err:  "cannot index '[0]'",
			},
			{
				path: `.common_properties.metadata.typed_filter_metadata["map<string, Any>"].(envoy.config.endpoint.v3.ClusterLoadAssignment).named_endpoints["key2"].additional_addresses[0].(envoy.config.core.v3.Address)`,
				err:  "can only expand fields of type google.protobuf.Any, not repeated envoy.config.endpoint.v3.Endpoint.AdditionalAddress",
			},
			{
				path: `.common_properties.metadata.typed_filter_metadata["repeated Any"].(envoy.admin.v3.ConfigDump).configs.(envoy.admin.v3.ConfigDump)`,
				err:  "can only expand fields of type google.protobuf.Any, not repeated google.protobuf.Any",
			},
			{
				path: ".common_properties.metadata.typed_filter_metadata.(envoy.config.endpoint.v3.ClusterLoadAssignment)",
				err:  "can only expand fields of type google.protobuf.Any, not map<string, google.protobuf.Any>",
			},
			{
				path: ".common_properties.route_name.(google.protobuf.StringValue)",
				err:  "can only expand fields of type google.protobuf.Any, not string",
			},
			{
				path: `.common_properties.metadata.typed_filter_metadata["repeated Any"].(envoy.admin.v3.ConfigDump).configs["not-an-integer"]`,
				err:  `invalid list index: strconv.ParseInt: parsing "\"not-an-integer\"": invalid syntax`,
			},
			{
				path: ".common_properties.custom_tags[]",
				err:  "empty map key",
			},
			{
				path: ".common_properties.custom_tags[1234]",
				err:  "invalid string map key '1234': invalid syntax",
			},
			{
				path: `.common_properties.metadata.typed_filter_metadata["unusual fields"].bool_to_any[notABool]`,
				err:  "no such field 'bool_to_any' in message google.protobuf.Any (missing type expansion?)",
			},
			{
				path: `.common_properties.metadata.typed_filter_metadata["unusual fields"].(testdata.UnusualFields).nonexistent`,
				err:  "no such field 'nonexistent' in message testdata.UnusualFields",
			},
			{
				path: `.common_properties.metadata.typed_filter_metadata["unusual fields"].(testdata.UnusualFields).bool_to_any[notABool]`,
				err:  "invalid map key 'notABool' for bool field 'testdata.UnusualFields.bool_to_any'",
			},
			{
				path: `.common_properties.metadata.typed_filter_metadata["unusual fields"].(testdata.UnusualFields).int32_to_any[true]`,
				err:  "invalid map key 'true': strconv.ParseInt: parsing \"true\": invalid syntax",
			},
			{
				path: `.common_properties.metadata.typed_filter_metadata["unusual fields"].(testdata.UnusualFields).int64_to_any[false]`,
				err:  "invalid map key 'false': strconv.ParseInt: parsing \"false\": invalid syntax",
			},
			{
				path: `.common_properties.metadata.typed_filter_metadata["unusual fields"].(testdata.UnusualFields).uint32_to_any[-1]`,
				err:  "invalid map key '-1': strconv.ParseUint: parsing \"-1\": invalid syntax",
			},
			{
				path: `.common_properties.metadata.typed_filter_metadata["unusual fields"].(testdata.UnusualFields).uint64_to_any["foo"]`,
				err:  `invalid map key '"foo"': strconv.ParseUint: parsing "\"foo\"": invalid syntax`,
			},
			{
				path: `.common_properties.metadata.typed_filter_metadata["unusual fields"].(testdata.UnusualFields).bool_to_int64[true].field`,
				err:  "cannot access field 'field' of non-message type",
			},
			{
				path: ".common_properties.?.route_name",
				err:  "unknown field access not supported",
			},
			{
				path: ".(envoy.data.accesslog.v3.HTTPAccessLogEntry)",
				err:  "unexpected type expansion after Root step",
			},
			{
				path: `.common_properties.metadata.typed_filter_metadata["repeated Any"].(.envoy.admin.v3.ConfigDump)`,
				err:  "invalid message type '.envoy.admin.v3.ConfigDump' (try removing the leading dot)",
			},
			{
				path: `.common_properties.metadata.typed_filter_metadata["repeated Any"].(envoy.admin.ConfigDump.)`,
				err:  "invalid message type 'envoy.admin.ConfigDump.'",
			},
			{
				path: `.common_properties.metadata.typed_filter_metadata["repeated Any"].(testdata.UnusualFields).bool_to_int64[false]`,
				err:  "wrong message type: expecting envoy.admin.v3.ConfigDump, have testdata.UnusualFields",
			},
			{
				path: `.common_properties.metadata.typed_filter_metadata["repeated Any"].(foo.bar.Nonexistent)`,
				err:  "message type foo.bar.Nonexistent not found",
			},
			{
				path: `.common_properties.metadata.typed_filter_metadata["repeated Any"].(envoy.data.accesslog.v3.HTTPAccessLogEntry.HTTPVersion)`,
				err:  "error looking up message type envoy.data.accesslog.v3.HTTPAccessLogEntry.HTTPVersion: proto: found wrong type: got enum, want message",
			},
		}

		for _, c := range cases {
			t.Run(c.path, func(t *testing.T) {
				path, err := protoutil.ParsePath(entry.ProtoReflect(), c.path)
				if err != nil {
					// note: protobuf randomly swaps out spaces in error messages with
					// non-breaking spaces (U+00A0)
					assert.Contains(t, strings.ReplaceAll(err.Error(), "\u00a0", " "), c.err)
				} else {
					_, err := protoutil.DereferencePath(entry, path)
					if assert.Error(t, err) {
						assert.Contains(t, strings.ReplaceAll(err.Error(), "\u00a0", " "), c.err)
					}
				}
			})
		}
	})
	t.Run("Invalid input", func(t *testing.T) {
		longPath := `.common_properties.metadata.typed_filter_metadata["map<string, Any>"].(envoy.config.endpoint.v3.ClusterLoadAssignment).named_endpoints["key2"].additional_addresses[0].address.socket_address.address`
		steps := []proto.Message{
			(*envoy_data_accesslog_v3.HTTPAccessLogEntry)(nil),
			&envoy_data_accesslog_v3.HTTPAccessLogEntry{},
			&envoy_data_accesslog_v3.HTTPAccessLogEntry{
				CommonProperties: &envoy_data_accesslog_v3.AccessLogCommon{},
			},
			&envoy_data_accesslog_v3.HTTPAccessLogEntry{
				CommonProperties: &envoy_data_accesslog_v3.AccessLogCommon{
					Metadata: &envoy_config_core_v3.Metadata{},
				},
			},
			&envoy_data_accesslog_v3.HTTPAccessLogEntry{
				CommonProperties: &envoy_data_accesslog_v3.AccessLogCommon{
					Metadata: &envoy_config_core_v3.Metadata{
						TypedFilterMetadata: map[string]*anypb.Any{},
					},
				},
			},
			&envoy_data_accesslog_v3.HTTPAccessLogEntry{
				CommonProperties: &envoy_data_accesslog_v3.AccessLogCommon{
					Metadata: &envoy_config_core_v3.Metadata{
						TypedFilterMetadata: map[string]*anypb.Any{
							"map<string, Any>": nil,
						},
					},
				},
			},
			&envoy_data_accesslog_v3.HTTPAccessLogEntry{
				CommonProperties: &envoy_data_accesslog_v3.AccessLogCommon{
					Metadata: &envoy_config_core_v3.Metadata{
						TypedFilterMetadata: map[string]*anypb.Any{
							"map<string, Any>": protoutil.NewAny(&envoy_config_endpoint_v3.ClusterLoadAssignment{}),
						},
					},
				},
			},
			&envoy_data_accesslog_v3.HTTPAccessLogEntry{
				CommonProperties: &envoy_data_accesslog_v3.AccessLogCommon{
					Metadata: &envoy_config_core_v3.Metadata{
						TypedFilterMetadata: map[string]*anypb.Any{
							"map<string, Any>": protoutil.NewAny(&envoy_config_endpoint_v3.ClusterLoadAssignment{
								NamedEndpoints: map[string]*envoy_config_endpoint_v3.Endpoint{},
							}),
						},
					},
				},
			},
			&envoy_data_accesslog_v3.HTTPAccessLogEntry{
				CommonProperties: &envoy_data_accesslog_v3.AccessLogCommon{
					Metadata: &envoy_config_core_v3.Metadata{
						TypedFilterMetadata: map[string]*anypb.Any{
							"map<string, Any>": protoutil.NewAny(&envoy_config_endpoint_v3.ClusterLoadAssignment{
								NamedEndpoints: map[string]*envoy_config_endpoint_v3.Endpoint{
									"wrongKey": {},
								},
							}),
						},
					},
				},
			},
			&envoy_data_accesslog_v3.HTTPAccessLogEntry{
				CommonProperties: &envoy_data_accesslog_v3.AccessLogCommon{
					Metadata: &envoy_config_core_v3.Metadata{
						TypedFilterMetadata: map[string]*anypb.Any{
							"map<string, Any>": protoutil.NewAny(&envoy_config_endpoint_v3.ClusterLoadAssignment{
								NamedEndpoints: map[string]*envoy_config_endpoint_v3.Endpoint{
									"key2": {
										AdditionalAddresses: []*envoy_config_endpoint_v3.Endpoint_AdditionalAddress{},
									},
								},
							}),
						},
					},
				},
			},
			&envoy_data_accesslog_v3.HTTPAccessLogEntry{
				CommonProperties: &envoy_data_accesslog_v3.AccessLogCommon{
					Metadata: &envoy_config_core_v3.Metadata{
						TypedFilterMetadata: map[string]*anypb.Any{
							"map<string, Any>": protoutil.NewAny(&envoy_config_endpoint_v3.ClusterLoadAssignment{
								NamedEndpoints: map[string]*envoy_config_endpoint_v3.Endpoint{
									"key2": {
										AdditionalAddresses: []*envoy_config_endpoint_v3.Endpoint_AdditionalAddress{
											{},
										},
									},
								},
							}),
						},
					},
				},
			},
			&envoy_data_accesslog_v3.HTTPAccessLogEntry{
				CommonProperties: &envoy_data_accesslog_v3.AccessLogCommon{
					Metadata: &envoy_config_core_v3.Metadata{
						TypedFilterMetadata: map[string]*anypb.Any{
							"map<string, Any>": protoutil.NewAny(&envoy_config_endpoint_v3.ClusterLoadAssignment{
								NamedEndpoints: map[string]*envoy_config_endpoint_v3.Endpoint{
									"key2": {
										AdditionalAddresses: []*envoy_config_endpoint_v3.Endpoint_AdditionalAddress{{
											Address: &envoy_config_core_v3.Address{},
										}},
									},
								},
							}),
						},
					},
				},
			},
			&envoy_data_accesslog_v3.HTTPAccessLogEntry{
				CommonProperties: &envoy_data_accesslog_v3.AccessLogCommon{
					Metadata: &envoy_config_core_v3.Metadata{
						TypedFilterMetadata: map[string]*anypb.Any{
							"map<string, Any>": protoutil.NewAny(&envoy_config_endpoint_v3.ClusterLoadAssignment{
								NamedEndpoints: map[string]*envoy_config_endpoint_v3.Endpoint{
									"key2": {
										AdditionalAddresses: []*envoy_config_endpoint_v3.Endpoint_AdditionalAddress{{
											Address: &envoy_config_core_v3.Address{
												Address: &envoy_config_core_v3.Address_SocketAddress{
													SocketAddress: &envoy_config_core_v3.SocketAddress{
														Address: "foo",
													},
												},
											},
										}},
									},
								},
							}),
						},
					},
				},
			},
		}

		for i, c := range steps {
			t.Run(fmt.Sprint(i), func(t *testing.T) {
				path, err := protoutil.ParsePath(c.ProtoReflect(), longPath)
				require.NoError(t, err)

				v, err := protoutil.DereferencePath(c, path)
				assert.NoError(t, err)
				if i == len(steps)-1 {
					assert.True(t, v.IsValid(), "expected valid value")
					assert.Equal(t, "foo", v.String())
				} else {
					assert.False(t, v.IsValid(), "expected invalid value but got %q", v.String())
				}
			})
		}
	})
}
