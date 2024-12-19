package envoyconfig

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestBuildSubjectAltNameMatcher(t *testing.T) {
	b := new(Builder)
	testutil.AssertProtoJSONEqual(t, `{
		"sanType": "DNS",
		"matcher": {
			"exact": "example.com"
		}
	}`, b.buildSubjectAltNameMatcher(&url.URL{Host: "example.com:1234"}, ""))
	testutil.AssertProtoJSONEqual(t, `{
		"sanType": "IP_ADDRESS",
		"matcher": {
			"exact": "10.0.0.1"
		}
	}`, b.buildSubjectAltNameMatcher(&url.URL{Host: "10.0.0.1:1234"}, ""))
	testutil.AssertProtoJSONEqual(t, `{
		"sanType": "IP_ADDRESS",
		"matcher": {
			"exact": "fd12:3456:789a:1::1"
		}
	}`, b.buildSubjectAltNameMatcher(&url.URL{Host: "[fd12:3456:789a:1::1]:1234"}, ""))
	testutil.AssertProtoJSONEqual(t, `{
		"sanType": "IP_ADDRESS",
		"matcher": {
			"exact": "fe80::1ff:fe23:4567:890a"
		}
	}`, b.buildSubjectAltNameMatcher(&url.URL{Host: "[fe80::1ff:fe23:4567:890a%eth2]:1234"}, ""))
	testutil.AssertProtoJSONEqual(t, `{
		"sanType": "DNS",
		"matcher": {
			"exact": "example.org"
		}
	}`, b.buildSubjectAltNameMatcher(&url.URL{Host: "example.com:1234"}, "example.org"))
	testutil.AssertProtoJSONEqual(t, `{
		"sanType": "DNS",
		"matcher": {
			"safeRegex": {
				"googleRe2": {},
				"regex": ".*\\.example\\.org"
			}
		}
	}`, b.buildSubjectAltNameMatcher(&url.URL{Host: "example.com:1234"}, "*.example.org"))
}

func TestBuildSubjectNameIndication(t *testing.T) {
	b := new(Builder)
	assert.Equal(t, "example.com", b.buildSubjectNameIndication(&url.URL{Host: "example.com:1234"}, ""))
	assert.Equal(t, "example.org", b.buildSubjectNameIndication(&url.URL{Host: "example.com:1234"}, "example.org"))
	assert.Equal(t, "example.example.org", b.buildSubjectNameIndication(&url.URL{Host: "example.com:1234"}, "*.example.org"))
}

func TestValidateCertificate(t *testing.T) {
	cert, err := cryptutil.GenerateCertificate(nil, "example.com", func(tpl *x509.Certificate) {
		// set the must staple flag on the cert
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{
			Id: oidMustStaple,
		})
	})
	require.NoError(t, err)

	assert.Error(t, validateCertificate(cert), "should return an error for a must-staple TLS certificate that has no stapled OCSP response")
}

func Test_buildDownstreamTLSContext(t *testing.T) {
	b := New("local-grpc", "local-http", "local-metrics", filemgr.NewManager(), nil)

	cacheDir, _ := os.UserCacheDir()
	clientCAFileName := filepath.Join(cacheDir, "pomerium", "envoy", "files", "client-ca-313754424855313435355a5348.pem")

	t.Run("no-validation", func(t *testing.T) {
		downstreamTLSContext, err := b.buildDownstreamTLSContextMulti(context.Background(), &config.Config{Options: &config.Options{}}, nil)
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `{
			"commonTlsContext": {
				"tlsParams": {
					"cipherSuites": [
						"ECDHE-ECDSA-AES256-GCM-SHA384",
						"ECDHE-RSA-AES256-GCM-SHA384",
						"ECDHE-ECDSA-AES128-GCM-SHA256",
						"ECDHE-RSA-AES128-GCM-SHA256",
						"ECDHE-ECDSA-CHACHA20-POLY1305",
						"ECDHE-RSA-CHACHA20-POLY1305"
					],
					"tlsMinimumProtocolVersion": "TLSv1_2",
					"tlsMaximumProtocolVersion": "TLSv1_3"
				},
				"alpnProtocols": ["h2", "http/1.1"]
			}
		}`, downstreamTLSContext)
	})
	t.Run("client-ca", func(t *testing.T) {
		downstreamTLSContext, err := b.buildDownstreamTLSContextMulti(context.Background(), &config.Config{Options: &config.Options{
			DownstreamMTLS: config.DownstreamMTLSSettings{
				CA: "VEVTVAo=", // "TEST\n" (with a trailing newline)
			},
		}}, nil)
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `{
			"commonTlsContext": {
				"tlsParams": {
					"cipherSuites": [
						"ECDHE-ECDSA-AES256-GCM-SHA384",
						"ECDHE-RSA-AES256-GCM-SHA384",
						"ECDHE-ECDSA-AES128-GCM-SHA256",
						"ECDHE-RSA-AES128-GCM-SHA256",
						"ECDHE-ECDSA-CHACHA20-POLY1305",
						"ECDHE-RSA-CHACHA20-POLY1305"
					],
					"tlsMinimumProtocolVersion": "TLSv1_2",
					"tlsMaximumProtocolVersion": "TLSv1_3"
				},
				"alpnProtocols": ["h2", "http/1.1"],
				"validationContext": {
					"maxVerifyDepth": 1,
					"onlyVerifyLeafCertCrl": true,
					"trustChainVerification": "ACCEPT_UNTRUSTED",
					"trustedCa": {
						"filename": "`+clientCAFileName+`"
					}
				}
			}
		}`, downstreamTLSContext)
	})
	t.Run("client-ca-strict", func(t *testing.T) {
		downstreamTLSContext, err := b.buildDownstreamTLSContextMulti(context.Background(), &config.Config{Options: &config.Options{
			DownstreamMTLS: config.DownstreamMTLSSettings{
				CA:          "VEVTVAo=", // "TEST\n" (with a trailing newline)
				Enforcement: config.MTLSEnforcementRejectConnection,
			},
		}}, nil)
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `{
			"commonTlsContext": {
				"tlsParams": {
					"cipherSuites": [
						"ECDHE-ECDSA-AES256-GCM-SHA384",
						"ECDHE-RSA-AES256-GCM-SHA384",
						"ECDHE-ECDSA-AES128-GCM-SHA256",
						"ECDHE-RSA-AES128-GCM-SHA256",
						"ECDHE-ECDSA-CHACHA20-POLY1305",
						"ECDHE-RSA-CHACHA20-POLY1305"
					],
					"tlsMinimumProtocolVersion": "TLSv1_2",
					"tlsMaximumProtocolVersion": "TLSv1_3"
				},
				"alpnProtocols": ["h2", "http/1.1"],
				"validationContext": {
					"maxVerifyDepth": 1,
					"onlyVerifyLeafCertCrl": true,
					"trustedCa": {
						"filename": "`+clientCAFileName+`"
					}
				}
			},
			"requireClientCertificate": true
		}`, downstreamTLSContext)
	})
	t.Run("policy-client-ca", func(t *testing.T) {
		downstreamTLSContext, err := b.buildDownstreamTLSContextMulti(context.Background(), &config.Config{Options: &config.Options{
			Policies: []config.Policy{
				{
					From:                  "https://a.example.com:1234",
					TLSDownstreamClientCA: "VEVTVA==", // "TEST" (no trailing newline)
				},
			},
		}}, nil)
		require.NoError(t, err)

		testutil.AssertProtoJSONEqual(t, `{
			"commonTlsContext": {
				"tlsParams": {
					"cipherSuites": [
						"ECDHE-ECDSA-AES256-GCM-SHA384",
						"ECDHE-RSA-AES256-GCM-SHA384",
						"ECDHE-ECDSA-AES128-GCM-SHA256",
						"ECDHE-RSA-AES128-GCM-SHA256",
						"ECDHE-ECDSA-CHACHA20-POLY1305",
						"ECDHE-RSA-CHACHA20-POLY1305"
					],
					"tlsMinimumProtocolVersion": "TLSv1_2",
					"tlsMaximumProtocolVersion": "TLSv1_3"
				},
				"alpnProtocols": ["h2", "http/1.1"],
				"validationContext": {
					"maxVerifyDepth": 1,
					"onlyVerifyLeafCertCrl": true,
					"trustChainVerification": "ACCEPT_UNTRUSTED",
					"trustedCa": {
						"filename": "`+clientCAFileName+`"
					}
				}
			}
		}`, downstreamTLSContext)
	})
	t.Run("client-ca-max-verify-depth", func(t *testing.T) {
		var maxVerifyDepth uint32
		config := &config.Config{Options: &config.Options{
			DownstreamMTLS: config.DownstreamMTLSSettings{
				MaxVerifyDepth: &maxVerifyDepth,
				CA:             "VEVTVAo=", // "TEST\n"
			},
		}}

		maxVerifyDepth = 10
		downstreamTLSContext, err := b.buildDownstreamTLSContextMulti(context.Background(), config, nil)
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `{
			"maxVerifyDepth": 10,
			"onlyVerifyLeafCertCrl": true,
			"trustChainVerification": "ACCEPT_UNTRUSTED",
			"trustedCa": {
				"filename": "`+clientCAFileName+`"
			}
		}`, downstreamTLSContext.GetCommonTlsContext().GetValidationContext())

		maxVerifyDepth = 0
		downstreamTLSContext, err = b.buildDownstreamTLSContextMulti(context.Background(), config, nil)
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `{
			"onlyVerifyLeafCertCrl": true,
			"trustChainVerification": "ACCEPT_UNTRUSTED",
			"trustedCa": {
				"filename": "`+clientCAFileName+`"
			}
		}`, downstreamTLSContext.GetCommonTlsContext().GetValidationContext())
	})
	t.Run("client-ca-san-matchers", func(t *testing.T) {
		config := &config.Config{Options: &config.Options{
			DownstreamMTLS: config.DownstreamMTLSSettings{
				CA: "VEVTVAo=", // "TEST\n"
				MatchSubjectAltNames: []config.SANMatcher{
					{Type: config.SANTypeDNS, Pattern: `.*\.corp\.example\.com`},
					{Type: config.SANTypeEmail, Pattern: `.*@example\.com`},
					{Type: config.SANTypeIPAddress, Pattern: `10\.10\.42\..*`},
					{Type: config.SANTypeURI, Pattern: `spiffe://example\.com/.*`},
					{Type: config.SANTypeUserPrincipalName, Pattern: `^device-id$`},
				},
			},
		}}
		downstreamTLSContext, err := b.buildDownstreamTLSContextMulti(context.Background(), config, nil)
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `{
			"maxVerifyDepth": 1,
			"matchTypedSubjectAltNames": [
				{
					"matcher": {
						"safeRegex": {
							"googleRe2": {},
							"regex": ".*\\.corp\\.example\\.com"
						}
					},
					"sanType": "DNS"
				},
				{
					"matcher": {
						"safeRegex": {
							"googleRe2": {},
							"regex": ".*@example\\.com"
						}
					},
					"sanType": "EMAIL"
				},
				{
					"matcher": {
						"safeRegex": {
							"googleRe2": {},
							"regex": "10\\.10\\.42\\..*"
						}
					},
					"sanType": "IP_ADDRESS"
				},
				{
					"matcher": {
						"safeRegex": {
							"googleRe2": {},
							"regex": "spiffe://example\\.com/.*"
						}
					},
					"sanType": "URI"
				},
				{
					"matcher": {
						"safeRegex": {
							"googleRe2": {},
							"regex": "^device-id$"
						}
					},
					"sanType": "OTHER_NAME",
					"oid": "1.3.6.1.4.1.311.20.2.3"
				}
			],
			"onlyVerifyLeafCertCrl": true,
			"trustChainVerification": "ACCEPT_UNTRUSTED",
			"trustedCa": {
				"filename": "`+clientCAFileName+`"
			}
		}`, downstreamTLSContext.GetCommonTlsContext().GetValidationContext())
	})
	t.Run("http1", func(t *testing.T) {
		downstreamTLSContext, err := b.buildDownstreamTLSContextMulti(context.Background(), &config.Config{Options: &config.Options{
			Cert:      aExampleComCert,
			Key:       aExampleComKey,
			CodecType: config.CodecTypeHTTP1,
		}}, nil)
		require.NoError(t, err)

		testutil.AssertProtoJSONEqual(t, `{
			"commonTlsContext": {
				"tlsParams": {
					"cipherSuites": [
						"ECDHE-ECDSA-AES256-GCM-SHA384",
						"ECDHE-RSA-AES256-GCM-SHA384",
						"ECDHE-ECDSA-AES128-GCM-SHA256",
						"ECDHE-RSA-AES128-GCM-SHA256",
						"ECDHE-ECDSA-CHACHA20-POLY1305",
						"ECDHE-RSA-CHACHA20-POLY1305"
					],
					"tlsMinimumProtocolVersion": "TLSv1_2",
					"tlsMaximumProtocolVersion": "TLSv1_3"
				},
				"alpnProtocols": ["http/1.1"]
			}
		}`, downstreamTLSContext)
	})
	t.Run("http2", func(t *testing.T) {
		downstreamTLSContext, err := b.buildDownstreamTLSContextMulti(context.Background(), &config.Config{Options: &config.Options{
			Cert:      aExampleComCert,
			Key:       aExampleComKey,
			CodecType: config.CodecTypeHTTP2,
		}}, nil)
		require.NoError(t, err)

		testutil.AssertProtoJSONEqual(t, `{
			"commonTlsContext": {
				"tlsParams": {
					"cipherSuites": [
						"ECDHE-ECDSA-AES256-GCM-SHA384",
						"ECDHE-RSA-AES256-GCM-SHA384",
						"ECDHE-ECDSA-AES128-GCM-SHA256",
						"ECDHE-RSA-AES128-GCM-SHA256",
						"ECDHE-ECDSA-CHACHA20-POLY1305",
						"ECDHE-RSA-CHACHA20-POLY1305"
					],
					"tlsMinimumProtocolVersion": "TLSv1_2",
					"tlsMaximumProtocolVersion": "TLSv1_3"
				},
				"alpnProtocols": ["h2"]
			}
		}`, downstreamTLSContext)
	})
}

func Test_clientCABundle(t *testing.T) {
	// Make sure multiple bundled CAs are separated by newlines.
	clientCA1 := []byte("client CA 1")
	clientCA2 := []byte("client CA 2")
	clientCA3 := []byte("client CA 3")

	b64 := base64.StdEncoding.EncodeToString
	cfg := &config.Config{Options: &config.Options{
		DownstreamMTLS: config.DownstreamMTLSSettings{
			CA: b64(clientCA3),
		},
		Policies: []config.Policy{
			{
				From:                  "https://foo.example.com",
				TLSDownstreamClientCA: b64(clientCA2),
			},
			{
				From:                  "https://bar.example.com",
				TLSDownstreamClientCA: b64(clientCA1),
			},
		},
	}}
	expected := []byte("client CA 3\nclient CA 2\nclient CA 1\n")
	actual := clientCABundle(context.Background(), cfg)
	assert.Equal(t, expected, actual)
}

func Test_getAllCertificates(t *testing.T) {
	t.Run("fallback cert", func(t *testing.T) {
		// If no certificate is configured, a fallback certificate should be generated.
		cfg := &config.Config{Options: &config.Options{
			SharedKey: base64.StdEncoding.EncodeToString([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")),
		}}
		certs, err := getAllCertificates(cfg)

		require.NoError(t, err)
		require.Len(t, certs, 1)
		parsed, err := x509.ParseCertificate(certs[0].Certificate[0])
		require.NoError(t, err)
		assert.Equal(t, "CN=Pomerium PSK CA,O=Pomerium", parsed.Issuer.String())
		assert.Equal(t, "O=Pomerium", parsed.Subject.String())
	})
	t.Run("no fallback cert", func(t *testing.T) {
		// If some certificate is configured, the fallback certificate should not be generated.
		cfg := &config.Config{Options: &config.Options{
			Cert: base64.StdEncoding.EncodeToString([]byte(testServerCert)),
			Key:  base64.StdEncoding.EncodeToString([]byte(testServerKey)),
		}}
		certs, err := getAllCertificates(cfg)

		require.NoError(t, err)
		require.Len(t, certs, 1)
		parsed, err := x509.ParseCertificate(certs[0].Certificate[0])
		require.NoError(t, err)
		assert.Equal(t, "CN=Test Root CA", parsed.Issuer.String())
		assert.Equal(t, "CN=server cert 1", parsed.Subject.String())
	})
	t.Run("derive internal domain cert", func(t *testing.T) {
		// If the generated certificate is explicitly configured, then it should still be added.
		cfg := &config.Config{Options: &config.Options{
			Cert:      base64.StdEncoding.EncodeToString([]byte(testServerCert)),
			Key:       base64.StdEncoding.EncodeToString([]byte(testServerKey)),
			SharedKey: base64.StdEncoding.EncodeToString([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")),

			DeriveInternalDomainCert: ptr("example.com"),
		}}
		certs, err := getAllCertificates(cfg)

		require.NoError(t, err)
		require.Len(t, certs, 2)
		parsed, err := x509.ParseCertificate(certs[0].Certificate[0])
		require.NoError(t, err)
		assert.Equal(t, "CN=Test Root CA", parsed.Issuer.String())
		assert.Equal(t, "CN=server cert 1", parsed.Subject.String())
		parsed, err = x509.ParseCertificate(certs[1].Certificate[0])
		require.NoError(t, err)
		assert.Equal(t, "CN=Pomerium PSK CA,O=Pomerium", parsed.Issuer.String())
		assert.Equal(t, "O=Pomerium", parsed.Subject.String())
	})
}

var testServerCert = `-----BEGIN CERTIFICATE-----
MIIBezCCASCgAwIBAgICEAEwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAxMMVGVzdCBS
b290IENBMCIYDzAwMDEwMTAxMDAwMDAwWhgPMDAwMTAxMDEwMDAwMDBaMBgxFjAU
BgNVBAMTDXNlcnZlciBjZXJ0IDEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARI
J6Cnzb7wY/C7DMxbZT3UFhEsUHq6hP80dtzmK3ix5v47q30wuYBXOwZckvvMSTXv
h8vYNLDRk2Zk8FF4rP9Ro1cwVTATBgNVHSUEDDAKBggrBgEFBQcDATAfBgNVHSME
GDAWgBT25A7+YE2uHr8pRVFJzt8xHsdPtzAdBgNVHREEFjAUghJzZXJ2ZXIuZXhh
bXBsZS5jb20wCgYIKoZIzj0EAwIDSQAwRgIhAJwuu9y6AP9GGdo88YmB14uWC/fx
ZNhtP7zjrvgObX7UAiEA4gFcmeZnWbcpuVSZDEFfMIfd/Nys8bpg3S8N/PSnJng=
-----END CERTIFICATE-----`

var testServerKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINl/ONFeqvjTLCPaIkcUnEdqXhQ8P3M/3qCjNNYfuJKvoAoGCCqGSM49
AwEHoUQDQgAESCegp82+8GPwuwzMW2U91BYRLFB6uoT/NHbc5it4seb+O6t9MLmA
VzsGXJL7zEk174fL2DSw0ZNmZPBReKz/UQ==
-----END EC PRIVATE KEY-----`
