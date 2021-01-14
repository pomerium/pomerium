package controlplane

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func Test_buildPolicyTransportSocket(t *testing.T) {
	cacheDir, _ := os.UserCacheDir()
	customCA := filepath.Join(cacheDir, "pomerium", "envoy", "files", "custom-ca-32484c314b584447463735303142374c31414145374650305a525539554938594d524855353757313942494d473847535231.pem")
	trustedCA := filepath.Join(cacheDir, "pomerium", "envoy", "files", "ca-certificates-354c304c30465135515846423936454b4756525843304643554559383249303939514a525445524145524d46593941464552.crt")

	srv, _ := NewServer("TEST")

	t.Run("insecure", func(t *testing.T) {
		assert.Nil(t, srv.buildPolicyTransportSocket(&config.Policy{
			Destination: mustParseURL("http://example.com"),
		}))
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
								"filename": "`+trustedCA+`"
							}
						}
					},
					"sni": "example.com"
				}
			}
		`, srv.buildPolicyTransportSocket(&config.Policy{
			Destination: mustParseURL("https://example.com"),
		}))
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
								"filename": "`+trustedCA+`"
							}
						}
					},
					"sni": "use-this-name.example.com"
				}
			}
		`, srv.buildPolicyTransportSocket(&config.Policy{
			Destination:   mustParseURL("https://example.com"),
			TLSServerName: "use-this-name.example.com",
		}))
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
								"filename": "`+trustedCA+`"
							},
							"trustChainVerification": "ACCEPT_UNTRUSTED"
						}
					},
					"sni": "example.com"
				}
			}
		`, srv.buildPolicyTransportSocket(&config.Policy{
			Destination:   mustParseURL("https://example.com"),
			TLSSkipVerify: true,
		}))
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
			Destination: mustParseURL("https://example.com"),
			TLSCustomCA: base64.StdEncoding.EncodeToString([]byte{0, 0, 0, 0}),
		}))
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
								"filename": "`+trustedCA+`"
							}
						}
					},
					"sni": "example.com"
				}
			}
		`, srv.buildPolicyTransportSocket(&config.Policy{
			Destination:       mustParseURL("https://example.com"),
			ClientCertificate: clientCert,
		}))
	})
}

func Test_buildCluster(t *testing.T) {
	cacheDir, _ := os.UserCacheDir()
	trustedCA := filepath.Join(cacheDir, "pomerium", "envoy", "files", "ca-certificates-354c304c30465135515846423936454b4756525843304643554559383249303939514a525445524145524d46593941464552.crt")
	srv, _ := NewServer("TEST")
	t.Run("insecure", func(t *testing.T) {
		cluster := buildCluster("example", mustParseURL("http://example.com"), nil, true, config.GetEnvoyDNSLookupFamily(config.DNSLookupFamilyV4Only))
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
		u := mustParseURL("https://example.com")
		transportSocket := srv.buildPolicyTransportSocket(&config.Policy{
			Destination: u,
		})
		cluster := buildCluster("example", u, transportSocket, true, config.GetEnvoyDNSLookupFamily(config.DNSLookupFamilyAuto))
		testutil.AssertProtoJSONEqual(t, `
			{
				"name": "example",
				"type": "STRICT_DNS",
				"connectTimeout": "10s",
				"respectDnsTtl": true,
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
									"filename": "`+trustedCA+`"
								}
							}
						},
						"sni": "example.com"
					}
				},
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
							}
						}]
					}]
				}
			}
		`, cluster)
	})
	t.Run("ip address", func(t *testing.T) {
		cluster := buildCluster("example", mustParseURL("http://127.0.0.1"), nil, true, config.GetEnvoyDNSLookupFamily(config.DNSLookupFamilyAuto))
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
		cluster := buildCluster("example", mustParseURL("http://localhost"), nil, true, config.GetEnvoyDNSLookupFamily(config.DNSLookupFamilyAuto))
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
}
