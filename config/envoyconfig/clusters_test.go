package envoyconfig

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_extensions_clusters_common_dns_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/common/dns/v3"
	envoy_extensions_clusters_dns_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dns/v3"
	envoy_extensions_network_dns_resolver_cares_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/network/dns_resolver/cares/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/volatiletech/null/v9"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func Test_BuildClusters(t *testing.T) {
	// The admin address path is based on os.TempDir(), which will vary from
	// system to system, so replace this with a stable location.
	t.Setenv("TMPDIR", "/tmp")

	opts := config.NewDefaultOptions()
	ctx := t.Context()
	b := New("local-connect", "local-grpc", "local-http", "local-debug", "local-metrics", filemgr.NewManager(), nil, true)
	clusters, err := b.BuildClusters(ctx, &config.Config{Options: opts})
	require.NoError(t, err)
	testutil.AssertProtoJSONFileEqual(t, "testdata/clusters.json", clusters)
}

func Test_buildPolicyTransportSocket(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	cacheDir, _ := os.UserCacheDir()
	customCA := filepath.Join(cacheDir, "pomerium", "envoy", "files", "custom-ca-3133535332543131503345494c.pem")

	b := New("local-connect", "local-grpc", "local-http", "local-debug", "local-metrics", filemgr.NewManager(), nil, true)
	rootCABytes, _ := getCombinedCertificateAuthority(ctx, &config.Config{Options: &config.Options{}})
	rootCA := b.filemgr.BytesDataSource("ca.pem", rootCABytes).GetFilename()

	o1 := config.NewDefaultOptions()
	o2 := config.NewDefaultOptions()
	o2.CA = base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 0})

	combinedCABytes, _ := getCombinedCertificateAuthority(ctx, &config.Config{Options: &config.Options{CA: o2.CA}})
	combinedCA := b.filemgr.BytesDataSource("ca.pem", combinedCABytes).GetFilename()

	t.Run("insecure", func(t *testing.T) {
		ts, err := b.buildPolicyTransportSocket(ctx, &config.Config{Options: o1}, &config.Policy{
			To: mustParseWeightedURLs(t, "http://example.com"),
		}, *mustParseURL(t, "http://example.com"))
		require.NoError(t, err)
		assert.Nil(t, ts)
	})
	t.Run("host as sni", func(t *testing.T) {
		ts, err := b.buildPolicyTransportSocket(ctx, &config.Config{Options: o1}, &config.Policy{
			To: mustParseWeightedURLs(t, "https://example.com"),
		}, *mustParseURL(t, "https://example.com"))
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "tls",
				"typedConfig": {
					"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
					"commonTlsContext": {
						"alpnProtocols": ["h2", "http/1.1"],
						"tlsParams": {
							"cipherSuites": [
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
            	            	"AES256-SHA"
            	            ],
							"ecdhCurves": [
								"X25519",
								"P-256",
								"P-384",
								"P-521"
							],
							"tlsMinimumProtocolVersion": "TLSv1_2",
							"tlsMaximumProtocolVersion": "TLSv1_3"
						},
						"validationContext": {
							"matchTypedSubjectAltNames": [{
								"sanType": "DNS",
								"matcher": {
									"exact": "example.com"
								}
							}],
							"trustedCa": {
								"filename": "`+rootCA+`"
							}
						}
					},
					"sni": "example.com"
				}
			}
		`, ts)
	})
	t.Run("tls_server_name as sni", func(t *testing.T) {
		ts, err := b.buildPolicyTransportSocket(ctx, &config.Config{Options: o1}, &config.Policy{
			To:            mustParseWeightedURLs(t, "https://example.com"),
			TLSServerName: "use-this-name.example.com",
		}, *mustParseURL(t, "https://example.com"))
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "tls",
				"typedConfig": {
					"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
					"commonTlsContext": {
						"alpnProtocols": ["h2", "http/1.1"],
						"tlsParams": {
							"cipherSuites": [
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
								"AES256-SHA"
							],
							"ecdhCurves": [
								"X25519",
								"P-256",
								"P-384",
								"P-521"
							],
							"tlsMinimumProtocolVersion": "TLSv1_2",
							"tlsMaximumProtocolVersion": "TLSv1_3"
						},
						"validationContext": {
							"matchTypedSubjectAltNames": [{
								"sanType": "DNS",
								"matcher": {
									"exact": "use-this-name.example.com"
								}
							}],
							"trustedCa": {
								"filename": "`+rootCA+`"
							}
						}
					},
					"sni": "use-this-name.example.com"
				}
			}
		`, ts)
	})
	t.Run("tls_upstream_server_name as sni", func(t *testing.T) {
		ts, err := b.buildPolicyTransportSocket(ctx, &config.Config{Options: o1}, &config.Policy{
			To:                    mustParseWeightedURLs(t, "https://example.com"),
			TLSUpstreamServerName: "use-this-name.example.com",
		}, *mustParseURL(t, "https://example.com"))
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "tls",
				"typedConfig": {
					"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
					"commonTlsContext": {
						"alpnProtocols": ["h2", "http/1.1"],
						"tlsParams": {
							"cipherSuites": [
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
								"AES256-SHA"
							],
							"ecdhCurves": [
								"X25519",
								"P-256",
								"P-384",
								"P-521"
							],
							"tlsMinimumProtocolVersion": "TLSv1_2",
							"tlsMaximumProtocolVersion": "TLSv1_3"
						},
						"validationContext": {
							"matchTypedSubjectAltNames": [{
								"sanType": "DNS",
								"matcher": {
									"exact": "use-this-name.example.com"
								}
							}],
							"trustedCa": {
								"filename": "`+rootCA+`"
							}
						}
					},
					"sni": "use-this-name.example.com"
				}
			}
		`, ts)
	})
	t.Run("tls_skip_verify", func(t *testing.T) {
		ts, err := b.buildPolicyTransportSocket(ctx, &config.Config{Options: o1}, &config.Policy{
			To:            mustParseWeightedURLs(t, "https://example.com"),
			TLSSkipVerify: true,
		}, *mustParseURL(t, "https://example.com"))
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "tls",
				"typedConfig": {
					"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
					"commonTlsContext": {
						"alpnProtocols": ["h2", "http/1.1"],
						"tlsParams": {
							"cipherSuites": [
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
            	            	"AES256-SHA"
            	            ],
							"ecdhCurves": [
								"X25519",
								"P-256",
								"P-384",
								"P-521"
							],
							"tlsMinimumProtocolVersion": "TLSv1_2",
							"tlsMaximumProtocolVersion": "TLSv1_3"
						},
						"validationContext": {
							"matchTypedSubjectAltNames": [{
								"sanType": "DNS",
								"matcher": {
									"exact": "example.com"
								}
							}],
							"trustedCa": {
								"filename": "`+rootCA+`"
							},
							"trustChainVerification": "ACCEPT_UNTRUSTED"
						}
					},
					"sni": "example.com"
				}
			}
		`, ts)
	})
	t.Run("custom ca", func(t *testing.T) {
		ts, err := b.buildPolicyTransportSocket(ctx, &config.Config{Options: o1}, &config.Policy{
			To:          mustParseWeightedURLs(t, "https://example.com"),
			TLSCustomCA: base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 0}),
		}, *mustParseURL(t, "https://example.com"))
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "tls",
				"typedConfig": {
					"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
					"commonTlsContext": {
						"alpnProtocols": ["h2", "http/1.1"],
						"tlsParams": {
							"cipherSuites": [
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
								"AES256-SHA"
							],
							"ecdhCurves": [
								"X25519",
								"P-256",
								"P-384",
								"P-521"
							],
							"tlsMinimumProtocolVersion": "TLSv1_2",
							"tlsMaximumProtocolVersion": "TLSv1_3"
						},
						"validationContext": {
							"matchTypedSubjectAltNames": [{
								"sanType": "DNS",
								"matcher": {
									"exact": "example.com"
								}
							}],
							"trustedCa": {
								"filename": "`+customCA+`"
							}
						}
					},
					"sni": "example.com"
				}
			}
		`, ts)
	})
	t.Run("options custom ca", func(t *testing.T) {
		ts, err := b.buildPolicyTransportSocket(ctx, &config.Config{Options: o2}, &config.Policy{
			To: mustParseWeightedURLs(t, "https://example.com"),
		}, *mustParseURL(t, "https://example.com"))
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "tls",
				"typedConfig": {
					"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
					"commonTlsContext": {
						"alpnProtocols": ["h2", "http/1.1"],
						"tlsParams": {
							"cipherSuites": [
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
								"AES256-SHA"
							],
							"ecdhCurves": [
								"X25519",
								"P-256",
								"P-384",
								"P-521"
							],
							"tlsMinimumProtocolVersion": "TLSv1_2",
							"tlsMaximumProtocolVersion": "TLSv1_3"
						},
						"validationContext": {
							"matchTypedSubjectAltNames": [{
								"sanType": "DNS",
								"matcher": {
									"exact": "example.com"
								}
							}],
							"trustedCa": {
								"filename": "`+combinedCA+`"
							}
						}
					},
					"sni": "example.com"
				}
			}
		`, ts)
	})
	t.Run("client certificate", func(t *testing.T) {
		clientCert, _ := cryptutil.CertificateFromBase64(aExampleComCert, aExampleComKey)
		ts, err := b.buildPolicyTransportSocket(ctx, &config.Config{Options: o1}, &config.Policy{
			To:                mustParseWeightedURLs(t, "https://example.com"),
			ClientCertificate: clientCert,
		}, *mustParseURL(t, "https://example.com"))
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "tls",
				"typedConfig": {
					"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
					"commonTlsContext": {
						"alpnProtocols": ["h2", "http/1.1"],
						"tlsParams": {
							"cipherSuites": [
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
            	            	"AES256-SHA"
            	            ],
							"ecdhCurves": [
								"X25519",
								"P-256",
								"P-384",
								"P-521"
							],
							"tlsMinimumProtocolVersion": "TLSv1_2",
							"tlsMaximumProtocolVersion": "TLSv1_3"
						},
						"tlsCertificates": [{
							"certificateChain":{
								"filename": "`+filepath.Join(cacheDir, "pomerium", "envoy", "files", "tls-crt-5a353247453159375849565a.pem")+`"
							},
							"privateKey": {
								"filename": "`+filepath.Join(cacheDir, "pomerium", "envoy", "files", "tls-key-3159554e32473758435257364b.pem")+`"
							}
						}],
						"validationContext": {
							"matchTypedSubjectAltNames": [{
								"sanType": "DNS",
								"matcher": {
									"exact": "example.com"
								}
							}],
							"trustedCa": {
								"filename": "`+rootCA+`"
							}
						}
					},
					"sni": "example.com"
				}
			}
		`, ts)
	})
	t.Run("allow renegotiation", func(t *testing.T) {
		ts, err := b.buildPolicyTransportSocket(ctx, &config.Config{Options: o1}, &config.Policy{
			To:                            mustParseWeightedURLs(t, "https://example.com"),
			TLSUpstreamAllowRenegotiation: true,
		}, *mustParseURL(t, "https://example.com"))
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "tls",
				"typedConfig": {
					"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
					"allowRenegotiation": true,
					"commonTlsContext": {
						"alpnProtocols": ["h2", "http/1.1"],
						"tlsParams": {
							"cipherSuites": [
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
								"AES256-SHA"
							],
							"ecdhCurves": [
								"X25519",
								"P-256",
								"P-384",
								"P-521"
							],
							"tlsMinimumProtocolVersion": "TLSv1_2",
							"tlsMaximumProtocolVersion": "TLSv1_3"
						},
						"validationContext": {
							"matchTypedSubjectAltNames": [{
								"sanType": "DNS",
								"matcher": {
									"exact": "example.com"
								}
							}],
							"trustedCa": {
								"filename": "`+rootCA+`"
							}
						}
					},
					"sni": "example.com"
				}
			}
		`, ts)
	})
}

func Test_buildCluster(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	b := New("local-connect", "local-grpc", "local-http", "local-debug", "local-metrics", filemgr.NewManager(), nil, true)
	rootCABytes, _ := getCombinedCertificateAuthority(ctx, &config.Config{Options: &config.Options{}})
	rootCA := b.filemgr.BytesDataSource("ca.pem", rootCABytes).GetFilename()
	o1 := config.NewDefaultOptions()
	t.Run("insecure", func(t *testing.T) {
		endpoints, err := b.buildPolicyEndpoints(ctx, &config.Config{Options: o1}, &config.Policy{
			To: mustParseWeightedURLs(t, "http://example.com", "http://1.2.3.4"),
		})
		require.NoError(t, err)
		cluster := newDefaultEnvoyClusterConfig()
		err = b.buildCluster(cluster, "example", endpoints, upstreamProtocolHTTP2, config.DNSOptions{
			LookupFamily: config.DNSLookupFamilyV4Only,
		}, Keepalive(false))
		require.NoErrorf(t, err, "cluster %+v", cluster)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "example",
				"clusterType": {
 					"name": "envoy.clusters.dns",
					"typedConfig": {
						"@type": "type.googleapis.com/envoy.extensions.clusters.dns.v3.DnsCluster",
						"dnsLookupFamily": "V4_ONLY",
						"respectDnsTtl": true,
						"typedDnsResolverConfig": {
							"name": "envoy.network.dns_resolver.cares",
							"typedConfig": {
								"@type": "type.googleapis.com/envoy.extensions.network.dns_resolver.cares.v3.CaresDnsResolverConfig",
								"udpMaxQueries": 100
							}
						}
					}
				},
				"connectTimeout": "10s",
				"perConnectionBufferLimitBytes": 32768,
				"typedExtensionProtocolOptions": {
					"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
						"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
						"explicitHttpConfig": {
							"http2ProtocolOptions": {
								"allowConnect": true,
								"initialConnectionWindowSize": 1048576,
								"initialStreamWindowSize": 65536,
								"maxConcurrentStreams": 100
							}
						}
					}
				},
				"loadAssignment": {
					"clusterName": "example",
					"endpoints": [{
						"lbEndpoints": [{
							"endpoint": {
								"address": {
									"socketAddress": {
										"address": "example.com",
										"portValue": 80
									}
								},
								"hostname": "example.com"
							}
						}, {
							"endpoint": {
								"address": {
									"socketAddress": {
										"address": "1.2.3.4",
										"portValue": 80
									}
								},
								"hostname": "1.2.3.4"
							}
						}]
					}]
				}
			}
		`, cluster)
	})
	t.Run("secure", func(t *testing.T) {
		endpoints, err := b.buildPolicyEndpoints(ctx, &config.Config{Options: o1}, &config.Policy{
			To: mustParseWeightedURLs(t,
				"https://example.com",
				"https://example.com",
			),
		})
		require.NoError(t, err)
		cluster := newDefaultEnvoyClusterConfig()
		err = b.buildCluster(cluster, "example", endpoints, upstreamProtocolHTTP2, config.DNSOptions{
			LookupFamily: config.DNSLookupFamilyV4Preferred,
		}, Keepalive(true))
		require.NoErrorf(t, err, "cluster %+v", cluster)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "example",
				"clusterType": {
 					"name": "envoy.clusters.dns",
					"typedConfig": {
						"@type": "type.googleapis.com/envoy.extensions.clusters.dns.v3.DnsCluster",
						"dnsLookupFamily": "V4_PREFERRED",
						"respectDnsTtl": true,
						"typedDnsResolverConfig": {
							"name": "envoy.network.dns_resolver.cares",
							"typedConfig": {
								"@type": "type.googleapis.com/envoy.extensions.network.dns_resolver.cares.v3.CaresDnsResolverConfig",
								"udpMaxQueries": 100
							}
						}
					}
				},
				"connectTimeout": "10s",
				"perConnectionBufferLimitBytes": 32768,
				"transportSocketMatches": [{
					"name": "`+endpoints[0].TransportSocketName()+`",
					"match": {
						"`+endpoints[0].TransportSocketName()+`": true
					},
					"transportSocket": {
						"name": "tls",
						"typedConfig": {
							"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
							"commonTlsContext": {
								"alpnProtocols": ["h2", "http/1.1"],
									"tlsParams": {
										"cipherSuites": [
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
											"AES256-SHA"
										],
									"ecdhCurves": [
										"X25519",
										"P-256",
										"P-384",
										"P-521"
									],
									"tlsMinimumProtocolVersion": "TLSv1_2",
									"tlsMaximumProtocolVersion": "TLSv1_3"
								},
								"validationContext": {
									"matchTypedSubjectAltNames": [{
										"sanType": "DNS",
										"matcher": {
											"exact": "example.com"
										}
									}],
									"trustedCa": {
										"filename": "`+rootCA+`"
									}
								}
							},
							"sni": "example.com"
						}
					}
				}],
				"transportSocket": {
					"name": "tls",
					"typedConfig": {
						"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
						"commonTlsContext": {
							"alpnProtocols": ["h2", "http/1.1"],
								"tlsParams": {
									"cipherSuites": [
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
										"AES256-SHA"
									],
								"ecdhCurves": [
									"X25519",
									"P-256",
									"P-384",
									"P-521"
								],
								"tlsMinimumProtocolVersion": "TLSv1_2",
								"tlsMaximumProtocolVersion": "TLSv1_3"
							},
							"validationContext": {
								"matchTypedSubjectAltNames": [{
									"sanType": "DNS",
									"matcher": {
										"exact": "example.com"
									}
								}],
								"trustedCa": {
									"filename": "`+rootCA+`"
								}
							}
						},
						"sni": "example.com"
					}
				},
				"typedExtensionProtocolOptions": {
					"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
						"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
						"explicitHttpConfig": {
							"http2ProtocolOptions": {
								"allowConnect": true,
								"initialConnectionWindowSize": 1048576,
								"initialStreamWindowSize": 65536,
								"maxConcurrentStreams": 100,
								"connectionKeepalive": {
									"connectionIdleInterval": "300s",
									"interval": "360s",
									"intervalJitter": {
										"value": 15
									},
									"timeout": "60s"
								}
							}
						}
					}
				},
				"loadAssignment": {
					"clusterName": "example",
					"endpoints": [{
						"lbEndpoints": [{
							"endpoint": {
								"address": {
									"socketAddress": {
										"address": "example.com",
										"portValue": 443
									}
								},
								"hostname": "example.com"
							},
							"metadata": {
								"filterMetadata": {
									"envoy.transport_socket_match": {
										"`+endpoints[0].TransportSocketName()+`": true
									}
								}
							}
						},{
							"endpoint": {
								"address": {
									"socketAddress": {
										"address": "example.com",
										"portValue": 443
									}
								},
								"hostname": "example.com"
							},
							"metadata": {
								"filterMetadata": {
									"envoy.transport_socket_match": {
										"`+endpoints[0].TransportSocketName()+`": true
									}
								}
							}
						}]
					}]
				}
			}
		`, cluster)
	})
	t.Run("ip addresses", func(t *testing.T) {
		endpoints, err := b.buildPolicyEndpoints(ctx, &config.Config{Options: o1}, &config.Policy{
			To: mustParseWeightedURLs(t, "http://127.0.0.1", "http://127.0.0.2"),
		})
		require.NoError(t, err)
		cluster := newDefaultEnvoyClusterConfig()
		err = b.buildCluster(cluster, "example", endpoints, upstreamProtocolHTTP2, config.DNSOptions{}, Keepalive(false))
		require.NoErrorf(t, err, "cluster %+v", cluster)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "example",
				"clusterType": {
 					"name": "envoy.cluster.static"
				},
				"connectTimeout": "10s",
				"perConnectionBufferLimitBytes": 32768,
				"typedExtensionProtocolOptions": {
					"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
						"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
						"explicitHttpConfig": {
							"http2ProtocolOptions": {
								"allowConnect": true,
								"initialConnectionWindowSize": 1048576,
								"initialStreamWindowSize": 65536,
								"maxConcurrentStreams": 100
							}
						}
					}
				},
				"loadAssignment": {
					"clusterName": "example",
					"endpoints": [{
						"lbEndpoints": [{
							"endpoint": {
								"address": {
									"socketAddress": {
										"address": "127.0.0.1",
										"portValue": 80
									}
								},
								"hostname": "127.0.0.1"
							}
						},{
							"endpoint": {
								"address": {
									"socketAddress": {
										"address": "127.0.0.2",
										"portValue": 80
									}
								},
								"hostname": "127.0.0.2"
							}
						}]
					}]
				}
			}
		`, cluster)
	})
	t.Run("weights", func(t *testing.T) {
		endpoints, err := b.buildPolicyEndpoints(ctx, &config.Config{Options: o1}, &config.Policy{
			To: mustParseWeightedURLs(t, "http://127.0.0.1:8080,1", "http://127.0.0.2,2"),
		})
		require.NoError(t, err)
		cluster := newDefaultEnvoyClusterConfig()
		err = b.buildCluster(cluster, "example", endpoints, upstreamProtocolHTTP2, config.DNSOptions{}, Keepalive(false))
		require.NoErrorf(t, err, "cluster %+v", cluster)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "example",
				"clusterType": {
 					"name": "envoy.cluster.static"
				},
				"connectTimeout": "10s",
				"perConnectionBufferLimitBytes": 32768,
				"typedExtensionProtocolOptions": {
					"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
						"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
						"explicitHttpConfig": {
							"http2ProtocolOptions": {
								"allowConnect": true,
								"initialConnectionWindowSize": 1048576,
								"initialStreamWindowSize": 65536,
								"maxConcurrentStreams": 100
							}
						}
					}
				},
				"loadAssignment": {
					"clusterName": "example",
					"endpoints": [{
						"lbEndpoints": [{
							"endpoint": {
								"address": {
									"socketAddress": {
										"address": "127.0.0.1",
										"portValue": 8080
									}
								},
								"hostname": "127.0.0.1:8080"
							},
							"loadBalancingWeight": 1
						},{
							"endpoint": {
								"address": {
									"socketAddress": {
										"address": "127.0.0.2",
										"portValue": 80
									}
								},
								"hostname": "127.0.0.2"
							},
							"loadBalancingWeight": 2
						}]
					}]
				}
			}
		`, cluster)
	})
	t.Run("localhost", func(t *testing.T) {
		endpoints, err := b.buildPolicyEndpoints(ctx, &config.Config{Options: o1}, &config.Policy{
			To: mustParseWeightedURLs(t, "http://localhost"),
		})
		require.NoError(t, err)
		cluster := newDefaultEnvoyClusterConfig()
		err = b.buildCluster(cluster, "example", endpoints, upstreamProtocolHTTP2, config.DNSOptions{}, Keepalive(false))
		require.NoErrorf(t, err, "cluster %+v", cluster)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "example",
				"clusterType": {
 					"name": "envoy.cluster.static"
				},
				"connectTimeout": "10s",
				"perConnectionBufferLimitBytes": 32768,
				"typedExtensionProtocolOptions": {
					"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
						"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
						"explicitHttpConfig": {
							"http2ProtocolOptions": {
								"allowConnect": true,
								"initialConnectionWindowSize": 1048576,
								"initialStreamWindowSize": 65536,
								"maxConcurrentStreams": 100
							}
						}
					}
				},
				"loadAssignment": {
					"clusterName": "example",
					"endpoints": [{
						"lbEndpoints": [{
							"endpoint": {
								"address": {
									"socketAddress": {
										"address": "127.0.0.1",
										"portValue": 80
									}
								},
								"hostname": "localhost"
							}
						}]
					}]
				}
			}
		`, cluster)
	})
	t.Run("outlier", func(t *testing.T) {
		endpoints, err := b.buildPolicyEndpoints(ctx, &config.Config{Options: o1}, &config.Policy{
			To: mustParseWeightedURLs(t, "http://example.com"),
		})
		require.NoError(t, err)
		cluster := newDefaultEnvoyClusterConfig()
		cluster.OutlierDetection = &envoy_config_cluster_v3.OutlierDetection{
			EnforcingConsecutive_5Xx:       wrapperspb.UInt32(17),
			SplitExternalLocalOriginErrors: true,
		}
		err = b.buildCluster(cluster, "example", endpoints, upstreamProtocolHTTP2, config.DNSOptions{
			LookupFamily: config.DNSLookupFamilyV4Only,
		}, Keepalive(false))
		require.NoErrorf(t, err, "cluster %+v", cluster)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "example",
				"clusterType": {
 					"name": "envoy.clusters.dns",
					"typedConfig": {
						"@type": "type.googleapis.com/envoy.extensions.clusters.dns.v3.DnsCluster",
						"dnsLookupFamily": "V4_ONLY",
						"respectDnsTtl": true,
						"typedDnsResolverConfig": {
							"name": "envoy.network.dns_resolver.cares",
							"typedConfig": {
								"@type": "type.googleapis.com/envoy.extensions.network.dns_resolver.cares.v3.CaresDnsResolverConfig",
								"udpMaxQueries": 100
							}
						}
					}
				},
				"connectTimeout": "10s",
				"perConnectionBufferLimitBytes": 32768,
				"typedExtensionProtocolOptions": {
					"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": {
						"@type": "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
						"explicitHttpConfig": {
							"http2ProtocolOptions": {
								"allowConnect": true,
								"initialConnectionWindowSize": 1048576,
								"initialStreamWindowSize": 65536,
								"maxConcurrentStreams": 100
							}
						}
					}
				},
				"outlierDetection": {
					"enforcingConsecutive5xx": 17,
					"splitExternalLocalOriginErrors": true
				},
				"loadAssignment": {
					"clusterName": "example",
					"endpoints": [{
						"lbEndpoints": [{
							"endpoint": {
								"address": {
									"socketAddress": {
										"address": "example.com",
										"portValue": 80
									}
								},
								"hostname": "example.com"
							}
						}]
					}]
				}
			}
		`, cluster)
	})
}

func Test_validateClusters(t *testing.T) {
	t.Parallel()

	type c []*envoy_config_cluster_v3.Cluster
	testCases := []struct {
		clusters    c
		expectError bool
	}{
		{c{{Name: "one"}, {Name: "one"}}, true},
		{c{{Name: "one"}, {Name: "two"}}, false},
	}

	for _, tc := range testCases {
		err := validateClusters(tc.clusters)
		if tc.expectError {
			assert.Error(t, err, "%#v", tc.clusters)
		} else {
			assert.NoError(t, err, "%#v", tc.clusters)
		}
	}
}

func Test_bindConfig(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Second*10)
	defer clearTimeout()

	b := New("local-connect", "local-grpc", "local-http", "local-debug", "local-metrics", filemgr.NewManager(), nil, true)
	t.Run("no bind config", func(t *testing.T) {
		cluster, err := b.buildPolicyCluster(ctx, &config.Config{Options: &config.Options{}}, &config.Policy{
			From: "https://from.example.com",
			To:   mustParseWeightedURLs(t, "https://to.example.com"),
		})
		assert.NoError(t, err)
		assert.Nil(t, cluster.UpstreamBindConfig)
	})
	t.Run("freebind", func(t *testing.T) {
		cluster, err := b.buildPolicyCluster(ctx, &config.Config{Options: &config.Options{
			EnvoyBindConfigFreebind: null.BoolFrom(true),
		}}, &config.Policy{
			From: "https://from.example.com",
			To:   mustParseWeightedURLs(t, "https://to.example.com"),
		})
		assert.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"freebind": true
			}
		`, cluster.UpstreamBindConfig)
	})
	t.Run("freebind set but null", func(t *testing.T) {
		cluster, err := b.buildPolicyCluster(ctx, &config.Config{Options: &config.Options{
			EnvoyBindConfigFreebind: null.BoolFromPtr(nil),
		}}, &config.Policy{
			From: "https://from.example.com",
			To:   mustParseWeightedURLs(t, "https://to.example.com"),
		})
		assert.NoError(t, err)
		assert.Nil(t, cluster.UpstreamBindConfig.GetSourceAddress())
	})
	t.Run("source address", func(t *testing.T) {
		cluster, err := b.buildPolicyCluster(ctx, &config.Config{Options: &config.Options{
			EnvoyBindConfigSourceAddress: "192.168.0.1",
		}}, &config.Policy{
			From: "https://from.example.com",
			To:   mustParseWeightedURLs(t, "https://to.example.com"),
		})
		assert.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `
			{
				"sourceAddress": {
					"address": "192.168.0.1",
					"portValue": 0
				}
			}
		`, cluster.UpstreamBindConfig)
	})
}

func TestGetDNSCluster(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		in     config.DNSOptions
		expect *envoy_extensions_clusters_dns_v3.DnsCluster
	}{
		{
			config.DNSOptions{},
			&envoy_extensions_clusters_dns_v3.DnsCluster{
				DnsLookupFamily: *envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_V4_PREFERRED.Enum(),
				RespectDnsTtl:   true,
				TypedDnsResolverConfig: &envoy_config_core_v3.TypedExtensionConfig{
					Name: "envoy.network.dns_resolver.cares",
					TypedConfig: protoutil.NewAny(&envoy_extensions_network_dns_resolver_cares_v3.CaresDnsResolverConfig{
						UdpMaxQueries: wrapperspb.UInt32(100),
					}),
				},
			},
		},
		{
			config.DNSOptions{
				FailureRefreshRate: ptr(3 * time.Second),
			},
			&envoy_extensions_clusters_dns_v3.DnsCluster{
				DnsFailureRefreshRate: &envoy_extensions_clusters_dns_v3.DnsCluster_RefreshRate{BaseInterval: durationpb.New(3 * time.Second)},
				DnsLookupFamily:       *envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_V4_PREFERRED.Enum(),
				RespectDnsTtl:         true,
				TypedDnsResolverConfig: &envoy_config_core_v3.TypedExtensionConfig{
					Name: "envoy.network.dns_resolver.cares",
					TypedConfig: protoutil.NewAny(&envoy_extensions_network_dns_resolver_cares_v3.CaresDnsResolverConfig{
						UdpMaxQueries: wrapperspb.UInt32(100),
					}),
				},
			},
		},
		{
			config.DNSOptions{
				LookupFamily: "V6_ONLY",
			},
			&envoy_extensions_clusters_dns_v3.DnsCluster{
				DnsLookupFamily: *envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_V6_ONLY.Enum(),
				RespectDnsTtl:   true,
				TypedDnsResolverConfig: &envoy_config_core_v3.TypedExtensionConfig{
					Name: "envoy.network.dns_resolver.cares",
					TypedConfig: protoutil.NewAny(&envoy_extensions_network_dns_resolver_cares_v3.CaresDnsResolverConfig{
						UdpMaxQueries: wrapperspb.UInt32(100),
					}),
				},
			},
		},
		{
			config.DNSOptions{
				QueryTimeout: ptr(4 * time.Second),
			},
			&envoy_extensions_clusters_dns_v3.DnsCluster{
				DnsLookupFamily: *envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_V4_PREFERRED.Enum(),
				RespectDnsTtl:   true,
				TypedDnsResolverConfig: &envoy_config_core_v3.TypedExtensionConfig{
					Name: "envoy.network.dns_resolver.cares",
					TypedConfig: protoutil.NewAny(&envoy_extensions_network_dns_resolver_cares_v3.CaresDnsResolverConfig{
						QueryTimeoutSeconds: wrapperspb.UInt64(4),
						UdpMaxQueries:       wrapperspb.UInt32(100),
					}),
				},
			},
		},
		{
			config.DNSOptions{
				QueryTries: null.Uint32From(33),
			},
			&envoy_extensions_clusters_dns_v3.DnsCluster{
				DnsLookupFamily: *envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_V4_PREFERRED.Enum(),
				RespectDnsTtl:   true,
				TypedDnsResolverConfig: &envoy_config_core_v3.TypedExtensionConfig{
					Name: "envoy.network.dns_resolver.cares",
					TypedConfig: protoutil.NewAny(&envoy_extensions_network_dns_resolver_cares_v3.CaresDnsResolverConfig{
						QueryTries:    wrapperspb.UInt32(33),
						UdpMaxQueries: wrapperspb.UInt32(100),
					}),
				},
			},
		},
		{
			config.DNSOptions{
				RefreshRate: ptr(5 * time.Second),
			},
			&envoy_extensions_clusters_dns_v3.DnsCluster{
				DnsLookupFamily: *envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_V4_PREFERRED.Enum(),
				DnsRefreshRate:  durationpb.New(5 * time.Second),
				RespectDnsTtl:   true,
				TypedDnsResolverConfig: &envoy_config_core_v3.TypedExtensionConfig{
					Name: "envoy.network.dns_resolver.cares",
					TypedConfig: protoutil.NewAny(&envoy_extensions_network_dns_resolver_cares_v3.CaresDnsResolverConfig{
						UdpMaxQueries: wrapperspb.UInt32(100),
					}),
				},
			},
		},
		{
			config.DNSOptions{
				UDPMaxQueries: null.Uint32From(111),
			},
			&envoy_extensions_clusters_dns_v3.DnsCluster{
				DnsLookupFamily: *envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_V4_PREFERRED.Enum(),
				RespectDnsTtl:   true,
				TypedDnsResolverConfig: &envoy_config_core_v3.TypedExtensionConfig{
					Name: "envoy.network.dns_resolver.cares",
					TypedConfig: protoutil.NewAny(&envoy_extensions_network_dns_resolver_cares_v3.CaresDnsResolverConfig{
						UdpMaxQueries: wrapperspb.UInt32(111),
					}),
				},
			},
		},
		{
			config.DNSOptions{
				UseTCP: null.BoolFrom(true),
			},
			&envoy_extensions_clusters_dns_v3.DnsCluster{
				DnsLookupFamily: *envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_V4_PREFERRED.Enum(),
				RespectDnsTtl:   true,
				TypedDnsResolverConfig: &envoy_config_core_v3.TypedExtensionConfig{
					Name: "envoy.network.dns_resolver.cares",
					TypedConfig: protoutil.NewAny(&envoy_extensions_network_dns_resolver_cares_v3.CaresDnsResolverConfig{
						DnsResolverOptions: &envoy_config_core_v3.DnsResolverOptions{
							UseTcpForDnsLookups: true,
						},
						UdpMaxQueries: wrapperspb.UInt32(100),
					}),
				},
			},
		},
		{
			config.DNSOptions{
				Resolvers: []string{"tcp://1.1.1.1:53", "udp://8.8.8.8:53"},
			},
			&envoy_extensions_clusters_dns_v3.DnsCluster{
				DnsLookupFamily: *envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_V4_PREFERRED.Enum(),
				RespectDnsTtl:   true,
				TypedDnsResolverConfig: &envoy_config_core_v3.TypedExtensionConfig{
					Name: "envoy.network.dns_resolver.cares",
					TypedConfig: protoutil.NewAny(&envoy_extensions_network_dns_resolver_cares_v3.CaresDnsResolverConfig{
						Resolvers: []*envoy_config_core_v3.Address{
							{
								Address: &envoy_config_core_v3.Address_SocketAddress{
									SocketAddress: &envoy_config_core_v3.SocketAddress{
										Protocol: envoy_config_core_v3.SocketAddress_TCP,
										Address:  "1.1.1.1",
										PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
											PortValue: 53,
										},
									},
								},
							},
							{
								Address: &envoy_config_core_v3.Address_SocketAddress{
									SocketAddress: &envoy_config_core_v3.SocketAddress{
										Protocol: envoy_config_core_v3.SocketAddress_UDP,
										Address:  "8.8.8.8",
										PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
											PortValue: 53,
										},
									},
								},
							},
						},
						UdpMaxQueries: wrapperspb.UInt32(100),
					}),
				},
			},
		},
		{
			config.DNSOptions{
				Resolvers: []string{"udp://[2001:4860:4860::8888]:53"},
			},
			&envoy_extensions_clusters_dns_v3.DnsCluster{
				DnsLookupFamily: *envoy_extensions_clusters_common_dns_v3.DnsLookupFamily_V4_PREFERRED.Enum(),
				RespectDnsTtl:   true,
				TypedDnsResolverConfig: &envoy_config_core_v3.TypedExtensionConfig{
					Name: "envoy.network.dns_resolver.cares",
					TypedConfig: protoutil.NewAny(&envoy_extensions_network_dns_resolver_cares_v3.CaresDnsResolverConfig{
						Resolvers: []*envoy_config_core_v3.Address{
							{
								Address: &envoy_config_core_v3.Address_SocketAddress{
									SocketAddress: &envoy_config_core_v3.SocketAddress{
										Protocol: envoy_config_core_v3.SocketAddress_UDP,
										Address:  "2001:4860:4860::8888",
										PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
											PortValue: 53,
										},
									},
								},
							},
						},
						UdpMaxQueries: wrapperspb.UInt32(100),
					}),
				},
			},
		},
	} {

		actual, err := GetDNSCluster(tc.in)
		require.NoError(t, err)
		assert.Empty(t, cmp.Diff(tc.expect, actual, protocmp.Transform()))
	}

	t.Run("invalid resolver", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			resolver string
		}{
			{"unsupported scheme", "http://example.com"},
			{"missing port", "tcp://1.1.1.1"},
			{"hostname", "tcp://dns.google:53"},
			{"invalid port", "udp://1.1.1.1:notaport"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := GetDNSCluster(config.DNSOptions{Resolvers: []string{tc.resolver}})
				require.Error(t, err)
			})
		}
	})
}

func mustParseWeightedURLs(t *testing.T, urls ...string) []config.WeightedURL {
	wu, err := config.ParseWeightedUrls(urls...)
	require.NoError(t, err)
	return wu
}

func Test_buildPolicyCluster(t *testing.T) {
	t.Parallel()

	b := New("local-connect", "local-grpc", "local-http", "local-debug", "local-metrics", filemgr.NewManager(), nil, true)

	t.Run("use stat name", func(t *testing.T) {
		t.Parallel()
		cluster, err := b.buildPolicyCluster(t.Context(), &config.Config{Options: config.NewDefaultOptions()}, &config.Policy{
			From:     "https://from.example.com",
			To:       mustParseWeightedURLs(t, "https://example.com"),
			StatName: null.StringFrom("stat-name"),
		})
		require.NoError(t, err)
		assert.Equal(t, "stat-name", cluster.AltStatName)
	})
}
