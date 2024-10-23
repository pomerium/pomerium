package envoyconfig

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/volatiletech/null/v9"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func Test_BuildClusters(t *testing.T) {
	// The admin address path is based on os.TempDir(), which will vary from
	// system to system, so replace this with a stable location.
	originalEnvoyAdminAddressPath := envoyAdminAddressPath
	envoyAdminAddressPath = "/tmp/pomerium-envoy-admin.sock"
	t.Cleanup(func() {
		envoyAdminAddressPath = originalEnvoyAdminAddressPath
	})

	opts := config.NewDefaultOptions()
	ctx := context.Background()
	b := New("local-grpc", "local-http", "local-metrics", filemgr.NewManager(), nil)
	clusters, err := b.BuildClusters(ctx, &config.Config{Options: opts})
	require.NoError(t, err)
	testutil.AssertProtoJSONFileEqual(t, "testdata/clusters.json", clusters)
}

func Test_buildPolicyTransportSocket(t *testing.T) {
	ctx := context.Background()
	cacheDir, _ := os.UserCacheDir()
	customCA := filepath.Join(cacheDir, "pomerium", "envoy", "files", "custom-ca-57394a4e5157303436544830.pem")

	b := New("local-grpc", "local-http", "local-metrics", filemgr.NewManager(), nil)
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
								"filename": "`+filepath.Join(cacheDir, "pomerium", "envoy", "files", "tls-crt-32375a484d4f49594c4d374830.pem")+`"
							},
							"privateKey": {
								"filename": "`+filepath.Join(cacheDir, "pomerium", "envoy", "files", "tls-key-33393156483053584631414836.pem")+`"
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
	ctx := context.Background()
	b := New("local-grpc", "local-http", "local-metrics", filemgr.NewManager(), nil)
	rootCABytes, _ := getCombinedCertificateAuthority(ctx, &config.Config{Options: &config.Options{}})
	rootCA := b.filemgr.BytesDataSource("ca.pem", rootCABytes).GetFilename()
	o1 := config.NewDefaultOptions()
	t.Run("insecure", func(t *testing.T) {
		endpoints, err := b.buildPolicyEndpoints(ctx, &config.Config{Options: o1}, &config.Policy{
			To: mustParseWeightedURLs(t, "http://example.com", "http://1.2.3.4"),
		})
		require.NoError(t, err)
		cluster := newDefaultEnvoyClusterConfig()
		cluster.DnsLookupFamily = envoy_config_cluster_v3.Cluster_V4_ONLY
		err = b.buildCluster(cluster, "example", endpoints, upstreamProtocolHTTP2, Keepalive(false))
		require.NoErrorf(t, err, "cluster %+v", cluster)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "example",
				"type": "STRICT_DNS",
				"connectTimeout": "10s",
				"respectDnsTtl": true,
				"dnsLookupFamily": "V4_ONLY",
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
		err = b.buildCluster(cluster, "example", endpoints, upstreamProtocolHTTP2, Keepalive(true))
		require.NoErrorf(t, err, "cluster %+v", cluster)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "example",
				"type": "STRICT_DNS",
				"connectTimeout": "10s",
				"respectDnsTtl": true,
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
									"interval": "60s",
									"intervalJitter": {
										"value": 15
									},
									"timeout": "60s"
								}
							}
						}
					}
				},
				"dnsLookupFamily": "V4_PREFERRED",
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
		err = b.buildCluster(cluster, "example", endpoints, upstreamProtocolHTTP2, Keepalive(false))
		require.NoErrorf(t, err, "cluster %+v", cluster)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "example",
				"type": "STATIC",
				"connectTimeout": "10s",
				"respectDnsTtl": true,
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
				"dnsLookupFamily": "V4_PREFERRED",
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
		err = b.buildCluster(cluster, "example", endpoints, upstreamProtocolHTTP2, Keepalive(false))
		require.NoErrorf(t, err, "cluster %+v", cluster)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "example",
				"type": "STATIC",
				"connectTimeout": "10s",
				"respectDnsTtl": true,
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
				"dnsLookupFamily": "V4_PREFERRED",
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
		err = b.buildCluster(cluster, "example", endpoints, upstreamProtocolHTTP2, Keepalive(false))
		require.NoErrorf(t, err, "cluster %+v", cluster)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "example",
				"type": "STATIC",
				"connectTimeout": "10s",
				"respectDnsTtl": true,
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
				"dnsLookupFamily": "V4_PREFERRED",
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
		cluster.DnsLookupFamily = envoy_config_cluster_v3.Cluster_V4_ONLY
		cluster.OutlierDetection = &envoy_config_cluster_v3.OutlierDetection{
			EnforcingConsecutive_5Xx:       wrapperspb.UInt32(17),
			SplitExternalLocalOriginErrors: true,
		}
		err = b.buildCluster(cluster, "example", endpoints, upstreamProtocolHTTP2, Keepalive(false))
		require.NoErrorf(t, err, "cluster %+v", cluster)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "example",
				"type": "STRICT_DNS",
				"connectTimeout": "10s",
				"respectDnsTtl": true,
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
				"dnsLookupFamily": "V4_ONLY",
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
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	defer clearTimeout()

	b := New("local-grpc", "local-http", "local-metrics", filemgr.NewManager(), nil)
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
				"freebind": true,
				"sourceAddress": {
					"address": "0.0.0.0",
					"portValue": 0
				}
			}
		`, cluster.UpstreamBindConfig)
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

func mustParseWeightedURLs(t *testing.T, urls ...string) []config.WeightedURL {
	wu, err := config.ParseWeightedUrls(urls...)
	require.NoError(t, err)
	return wu
}
