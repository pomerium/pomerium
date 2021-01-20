package controlplane

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func Test_buildPolicyTransportSocket(t *testing.T) {
	cacheDir, _ := os.UserCacheDir()
	customCA := filepath.Join(cacheDir, "pomerium", "envoy", "files", "custom-ca-32484c314b584447463735303142374c31414145374650305a525539554938594d524855353757313942494d473847535231.pem")

	srv, _ := NewServer("TEST")
	rootCAPath, _ := getRootCertificateAuthority()
	rootCA := srv.filemgr.FileDataSource(rootCAPath).GetFilename()

	t.Run("insecure", func(t *testing.T) {
		assert.Nil(t, srv.buildPolicyTransportSocket(&config.Policy{
			Destinations: mustParseURLs("http://example.com"),
		}, mustParseURL("http://example.com")))
	})
	t.Run("host as sni", func(t *testing.T) {
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "tls",
				"typedConfig": {
					"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
					"commonTlsContext": {
						"alpnProtocols": ["http/1.1"],
						"tlsParams": {
							"ecdhCurves": [
								"X25519",
								"P-256",
								"P-384",
								"P-521"
							]
						},
						"validationContext": {
							"matchSubjectAltNames": [{
								"exact": "example.com"
							}],
							"trustedCa": {
								"filename": "`+rootCA+`"
							}
						}
					},
					"sni": "example.com"
				}
			}
		`, srv.buildPolicyTransportSocket(&config.Policy{
			Destinations: mustParseURLs("https://example.com"),
		}, mustParseURL("https://example.com")))
	})
	t.Run("tls_server_name as sni", func(t *testing.T) {
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "tls",
				"typedConfig": {
					"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
					"commonTlsContext": {
						"alpnProtocols": ["http/1.1"],
						"tlsParams": {
							"ecdhCurves": [
								"X25519",
								"P-256",
								"P-384",
								"P-521"
							]
						},
						"validationContext": {
							"matchSubjectAltNames": [{
								"exact": "use-this-name.example.com"
							}],
							"trustedCa": {
								"filename": "`+rootCA+`"
							}
						}
					},
					"sni": "use-this-name.example.com"
				}
			}
		`, srv.buildPolicyTransportSocket(&config.Policy{
			Destinations:  mustParseURLs("https://example.com"),
			TLSServerName: "use-this-name.example.com",
		}, mustParseURL("https://example.com")))
	})
	t.Run("tls_skip_verify", func(t *testing.T) {
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "tls",
				"typedConfig": {
					"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
					"commonTlsContext": {
						"alpnProtocols": ["http/1.1"],
						"tlsParams": {
							"ecdhCurves": [
								"X25519",
								"P-256",
								"P-384",
								"P-521"
							]
						},
						"validationContext": {
							"matchSubjectAltNames": [{
								"exact": "example.com"
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
		`, srv.buildPolicyTransportSocket(&config.Policy{
			Destinations:  mustParseURLs("https://example.com"),
			TLSSkipVerify: true,
		}, mustParseURL("https://example.com")))
	})
	t.Run("custom ca", func(t *testing.T) {
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "tls",
				"typedConfig": {
					"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
					"commonTlsContext": {
						"alpnProtocols": ["http/1.1"],
						"tlsParams": {
							"ecdhCurves": [
								"X25519",
								"P-256",
								"P-384",
								"P-521"
							]
						},
						"validationContext": {
							"matchSubjectAltNames": [{
								"exact": "example.com"
							}],
							"trustedCa": {
								"filename": "`+customCA+`"
							}
						}
					},
					"sni": "example.com"
				}
			}
		`, srv.buildPolicyTransportSocket(&config.Policy{
			Destinations: mustParseURLs("https://example.com"),
			TLSCustomCA:  base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 0}),
		}, mustParseURL("https://example.com")))
	})
	t.Run("client certificate", func(t *testing.T) {
		clientCert, _ := cryptutil.CertificateFromBase64(aExampleComCert, aExampleComKey)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "tls",
				"typedConfig": {
					"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
					"commonTlsContext": {
						"alpnProtocols": ["http/1.1"],
						"tlsParams": {
							"ecdhCurves": [
								"X25519",
								"P-256",
								"P-384",
								"P-521"
							]
						},
						"tlsCertificates": [{
							"certificateChain":{
								"filename": "`+filepath.Join(cacheDir, "pomerium", "envoy", "files", "tls-crt-354e49305a5a39414a545530374e58454e48334148524c4e324258463837364355564c4e4532464b54355139495547514a38.pem")+`"
							},
							"privateKey": {
								"filename": "`+filepath.Join(cacheDir, "pomerium", "envoy", "files", "tls-key-3350415a38414e4e4a4655424e55393430474147324651433949384e485341334b5157364f424b4c5856365a545937383735.pem")+`"
							}
						}],
						"validationContext": {
							"matchSubjectAltNames": [{
								"exact": "example.com"
							}],
							"trustedCa": {
								"filename": "`+rootCA+`"
							}
						}
					},
					"sni": "example.com"
				}
			}
		`, srv.buildPolicyTransportSocket(&config.Policy{
			Destinations:      mustParseURLs("https://example.com"),
			ClientCertificate: clientCert,
		}, mustParseURL("https://example.com")))
	})
}

func Test_buildCluster(t *testing.T) {
	srv, _ := NewServer("TEST")
	rootCAPath, _ := getRootCertificateAuthority()
	rootCA := srv.filemgr.FileDataSource(rootCAPath).GetFilename()
	t.Run("insecure", func(t *testing.T) {
		endpoints := srv.buildPolicyEndpoints(&config.Policy{
			Destinations: mustParseURLs("http://example.com"),
		})
		cluster := buildCluster("example", endpoints, true,
			config.GetEnvoyDNSLookupFamily(config.DNSLookupFamilyV4Only),
			nil)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "example",
				"type": "STRICT_DNS",
				"connectTimeout": "10s",
				"respectDnsTtl": true,
				"http2ProtocolOptions": {
					"allowConnect": true
				},
				"dnsLookupFamily": "V4_ONLY",
				"loadAssignment": {
					"clusterName": "example",
					"endpoints": [{
						"lbEndpoints": [{
							"endpoint": {
								"address": {
									"socketAddress": {
										"address": "example.com",
										"ipv4Compat": true,
										"portValue": 80
									}
								}
							}
						}]
					}]
				}
			}
		`, cluster)
	})
	t.Run("secure", func(t *testing.T) {
		endpoints := srv.buildPolicyEndpoints(&config.Policy{
			Destinations: mustParseURLs("https://example.com"),
		})
		cluster := buildCluster("example", endpoints, true,
			config.GetEnvoyDNSLookupFamily(config.DNSLookupFamilyAuto),
			nil)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "example",
				"type": "STRICT_DNS",
				"connectTimeout": "10s",
				"respectDnsTtl": true,
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
								"alpnProtocols": ["http/1.1"],
								"tlsParams": {
								"ecdhCurves": [
									"X25519",
									"P-256",
									"P-384",
									"P-521"
								]
							},
								"validationContext": {
									"matchSubjectAltNames": [{
										"exact": "example.com"
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
				"http2ProtocolOptions": {
					"allowConnect": true
				},
				"loadAssignment": {
					"clusterName": "example",
					"endpoints": [{
						"lbEndpoints": [{
							"endpoint": {
								"address": {
									"socketAddress": {
										"address": "example.com",
										"ipv4Compat": true,
										"portValue": 443
									}
								}
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
	t.Run("ip address", func(t *testing.T) {
		endpoints := srv.buildPolicyEndpoints(&config.Policy{
			Destinations: mustParseURLs("http://127.0.0.1"),
		})
		cluster := buildCluster("example", endpoints, true,
			config.GetEnvoyDNSLookupFamily(config.DNSLookupFamilyAuto),
			nil)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "example",
				"type": "STATIC",
				"connectTimeout": "10s",
				"respectDnsTtl": true,
				"http2ProtocolOptions": {
					"allowConnect": true
				},
				"loadAssignment": {
					"clusterName": "example",
					"endpoints": [{
						"lbEndpoints": [{
							"endpoint": {
								"address": {
									"socketAddress": {
										"address": "127.0.0.1",
										"ipv4Compat": true,
										"portValue": 80
									}
								}
							}
						}]
					}]
				}
			}
		`, cluster)
	})
	t.Run("localhost", func(t *testing.T) {
		endpoints := srv.buildPolicyEndpoints(&config.Policy{
			Destinations: mustParseURLs("http://localhost"),
		})
		cluster := buildCluster("example", endpoints, true,
			config.GetEnvoyDNSLookupFamily(config.DNSLookupFamilyAuto),
			nil)
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "example",
				"type": "STATIC",
				"connectTimeout": "10s",
				"respectDnsTtl": true,
				"http2ProtocolOptions": {
					"allowConnect": true
				},
				"loadAssignment": {
					"clusterName": "example",
					"endpoints": [{
						"lbEndpoints": [{
							"endpoint": {
								"address": {
									"socketAddress": {
										"address": "127.0.0.1",
										"ipv4Compat": true,
										"portValue": 80
									}
								}
							}
						}]
					}]
				}
			}
		`, cluster)
	})
	t.Run("outlier", func(t *testing.T) {
		endpoints := srv.buildPolicyEndpoints(&config.Policy{
			Destinations: mustParseURLs("http://example.com"),
		})
		cluster := buildCluster("example", endpoints, true,
			config.GetEnvoyDNSLookupFamily(config.DNSLookupFamilyV4Only),
			&envoy_config_cluster_v3.OutlierDetection{
				EnforcingConsecutive_5Xx:       wrapperspb.UInt32(17),
				SplitExternalLocalOriginErrors: true,
			})
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "example",
				"type": "STRICT_DNS",
				"connectTimeout": "10s",
				"respectDnsTtl": true,
				"http2ProtocolOptions": {
					"allowConnect": true
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
										"ipv4Compat": true,
										"portValue": 80
									}
								}
							}
						}]
					}]
				}
			}
		`, cluster)
	})
}
