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
	rootCA, _ := getRootCertificateAuthority()
	cacheDir, _ := os.UserCacheDir()
	t.Run("insecure", func(t *testing.T) {
		assert.Nil(t, buildPolicyTransportSocket(&config.Policy{
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
								"P-512"
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
		`, buildPolicyTransportSocket(&config.Policy{
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
								"P-512"
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
		`, buildPolicyTransportSocket(&config.Policy{
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
								"P-512"
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
		`, buildPolicyTransportSocket(&config.Policy{
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
								"P-512"
							]
						},
						"validationContext": {
							"matchSubjectAltNames": [{
								"exact": "example.com"
							}],
							"trustedCa": {
								"filename": "`+filepath.Join(cacheDir, "pomerium", "envoy", "files", "custom-ca-3aefa6fd5cf2deb4.pem")+`"
							}
						}
					},
					"sni": "example.com"
				}
			}
		`, buildPolicyTransportSocket(&config.Policy{
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
								"P-512"
							]
						},
						"tlsCertificates": [{
							"certificateChain":{
								"filename": "`+filepath.Join(cacheDir, "pomerium", "envoy", "files", "tls-crt-921a8294d2e2ec54.pem")+`"
							},
							"privateKey": {
								"filename": "`+filepath.Join(cacheDir, "pomerium", "envoy", "files", "tls-key-d5cf35b1e8533e4a.pem")+`"
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
		`, buildPolicyTransportSocket(&config.Policy{
			Destination:       mustParseURL("https://example.com"),
			ClientCertificate: clientCert,
		}))
	})
}

func Test_buildCluster(t *testing.T) {
	rootCA, _ := getRootCertificateAuthority()
	t.Run("insecure", func(t *testing.T) {
		cluster := buildCluster("example", mustParseURL("http://example.com"), nil, true, true)
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
		transportSocket := buildPolicyTransportSocket(&config.Policy{
			Destination: u,
		})
		cluster := buildCluster("example", u, transportSocket, true, false)
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
								"P-512"
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
		cluster := buildCluster("example", mustParseURL("http://127.0.0.1"), nil, true, false)
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
		cluster := buildCluster("example", mustParseURL("http://localhost"), nil, true, false)
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
