package envoyconfig

import (
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"text/template"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

const (
	aExampleComCert = `LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVQVENDQXFXZ0F3SUJBZ0lSQUlWMDhHSVFYTWRVT0NXV3FocXlGR3N3RFFZSktvWklodmNOQVFFTEJRQXcKY3pFZU1Cd0dBMVVFQ2hNVmJXdGpaWEowSUdSbGRtVnNiM0J0Wlc1MElFTkJNU1F3SWdZRFZRUUxEQnRqWVd4bApZa0J3YjNBdGIzTWdLRU5oYkdWaUlFUnZlSE5sZVNreEt6QXBCZ05WQkFNTUltMXJZMlZ5ZENCallXeGxZa0J3CmIzQXRiM01nS0VOaGJHVmlJRVJ2ZUhObGVTa3dIaGNOTVRrd05qQXhNREF3TURBd1doY05NekF3TlRJeU1qRXoKT0RRMFdqQlBNU2N3SlFZRFZRUUtFeDV0YTJObGNuUWdaR1YyWld4dmNHMWxiblFnWTJWeWRHbG1hV05oZEdVeApKREFpQmdOVkJBc01HMk5oYkdWaVFIQnZjQzF2Y3lBb1EyRnNaV0lnUkc5NGMyVjVLVENDQVNJd0RRWUpLb1pJCmh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTm1HMWFKaXc0L29SMHFqUDMxUjRXeTZkOUVqZHc5K1kyelQKcjBDbGNYTDYxRk11R0YrKzJRclV6Y0VUZlZ2dGM1OXNQa0xkRHNtZ0Y2VlZCOTkyQ3ArWDlicWczWmQwSXZtbApVbjJvdTM5eUNEYnV2Q0E2d1gwbGNHL2JkRDE3TkRrS0poL3g5SDMzU3h4SG5UamlKdFBhbmt1MUI3ajdtRmM5Ck5jNXRyamFvUHBGaFJqMTJ1L0dWajRhWWs3SStpWHRpZHBjZXp2eWNDT0NtQlIwNHkzeWx5Q2sxSWNMTUhWOEEKNXphUFpVck15ZUtnTE1PTGlDSDBPeHhhUzh0Nk5vTjZudDdmOUp1TUxTN2V5SkxkQW05bGg0c092YXBPVklXZgpJQitaYnk5bkQ1dWl4N3V0a3llWTFOeE05SFZhUmZTQzcrejM4TDBWN3lJZlpCNkFLcWNDQXdFQUFhTndNRzR3CkRnWURWUjBQQVFIL0JBUURBZ1dnTUJNR0ExVWRKUVFNTUFvR0NDc0dBUVVGQndNQk1Bd0dBMVVkRXdFQi93UUMKTUFBd0h3WURWUjBqQkJnd0ZvQVVTaG9mWE5rY1hoMnE0d25uV1oyYmNvMjRYRVF3R0FZRFZSMFJCQkV3RDRJTgpZUzVsZUdGdGNHeGxMbU52YlRBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVlFQVA3aHVraThGeG54azRoVnJYUk93Ck51Uy9OUFhmQ3VaVDZWemJYUVUxbWNrZmhweVNDajVRZkFDQzdodVp6Qkp0NEtsUHViWHdRQ25YMFRMSmg1L0cKUzZBWEFXQ3VTSW5jTTZxNGs4MFAzVllWK3hXOS9rdERnTk1FTlNxSjdKR3lqdzBWWHlhOUZwdWd6Q3ZnN290RQo5STcrZTN0cmJnUDBHY3plSml6WTJBMVBWU082MVdKQ1lNQjNDLzcwVE9KMkZTNy82bURPTG9DSVJCY215cW5KClY2Vk5sRDl3Y2xmUWIrZUp0YlY0Vlg2RUY5UEYybUtncUNKT0FKLzBoMHAydTBhZGgzMkJDS2dIMDRSYUtuSS8KUzY1N0MrN1YzVEgzQ1VIVHgrdDRRRll4UEhRL0loQ3pYdUpVeFQzYWtYNEQ1czJkTHp2RnBJMFIzTVBwUE9VQQpUelpSdDI2T3FVNHlUdUFnb0kvZnZMdk55VTNZekF3ZUQ2Mndxc1hiVHAranNFcWpoODUvakpXWnA4RExKK0w3CmhXQW0rSVNKTzhrNWgwR0lIMFllb01heXBJbjRubWVsbHNSM1dvYzZRVTZ4cFFTd3V1NXE0ckJzOUxDWS9kZkwKNkEzMEhlYXVVK2sydGFUVlBMY2FCZm11NDJPaHMyYzQ0bzNPYnlvVkNDNi8KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=`
	aExampleComKey  = `LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktnd2dnU2tBZ0VBQW9JQkFRRFpodFdpWXNPUDZFZEsKb3o5OVVlRnN1bmZSSTNjUGZtTnMwNjlBcFhGeSt0UlRMaGhmdnRrSzFNM0JFMzFiN1hPZmJENUMzUTdKb0JlbApWUWZmZGdxZmwvVzZvTjJYZENMNXBWSjlxTHQvY2dnMjdyd2dPc0Y5SlhCdjIzUTllelE1Q2lZZjhmUjk5MHNjClI1MDQ0aWJUMnA1THRRZTQrNWhYUFRYT2JhNDJxRDZSWVVZOWRydnhsWStHbUpPeVBvbDdZbmFYSHM3OG5BamcKcGdVZE9NdDhwY2dwTlNIQ3pCMWZBT2MyajJWS3pNbmlvQ3pEaTRnaDlEc2NXa3ZMZWphRGVwN2UzL1NiakMwdQozc2lTM1FKdlpZZUxEcjJxVGxTRm55QWZtVzh2WncrYm9zZTdyWk1ubU5UY1RQUjFXa1gwZ3UvczkvQzlGZThpCkgyUWVnQ3FuQWdNQkFBRUNnZ0VCQUsrclFrLzNyck5EQkgvMFFrdTBtbll5U0p6dkpUR3dBaDlhL01jYVZQcGsKTXFCU000RHZJVnlyNnRZb0pTN2VIbWY3QkhUL0RQZ3JmNjBYZEZvMGUvUFN4ckhIUSswUjcwVHBEQ3RLM3REWAppR2JFZWMwVlpqam95VnFzUWIxOUIvbWdocFY1MHRiL3BQcmJvczdUWkVQbTQ3dUVJUTUwc055VEpDYm5VSy8xCnhla2ZmZ3hMbmZlRUxoaXhDNE1XYjMzWG9GNU5VdWduQ2pUakthUFNNUmpISm9YSFlGWjdZdEdlSEd1aDR2UGwKOU5TM0YxT2l0MWNnQzNCSm1BM28yZmhYbTRGR1FhQzNjYUdXTzE5eHAwRWE1eXQ0RHZOTWp5WlgvSkx1Qko0NQpsZU5jUSs3c3U0dW0vY0hqcFFVenlvZmoydFBIU085QXczWGY0L2lmN0hFQ2dZRUE1SWMzMzVKUUhJVlQwc003CnhkY3haYmppbUE5alBWMDFXSXh0di8zbzFJWm5TUGFocEFuYXVwZGZqRkhKZmJTYlZXaUJTaUZpb2RTR3pIdDgKTlZNTGFyVzVreDl5N1luYXdnZjJuQjc2VG03aFl6L3h5T3AxNXFRbmswVW9DdnQ2MHp6dDl5UE5KQ1pWalFwNgp4cUw4T1c4emNlUGpxZzJBTHRtcVhpNitZRXNDZ1lFQTg2ME5zSHMzNktFZE91Q1o1TXF6NVRLSmVYSzQ5ZkdBCjdxcjM5Sm9RcWYzbEhSSWozUlFlNERkWmQ5NUFXcFRKUEJXdnp6NVROOWdwNHVnb3VGc0tCaG82YWtsUEZTUFIKRkZwWCtGZE56eHJGTlAwZHhydmN0bXU2OW91MFR0QU1jd1hYWFJuR1BuK0xDTnVUUHZndHZTTnRwSEZMb0dzUQorVDFpTjhpWS9aVUNnWUJpMVJQVjdkb1ZxNWVuNCtWYTE0azJlL0lMWDBSRkNxV0NpU0VCMGxhNmF2SUtQUmVFCjhQb1dqbGExUWIzSlRxMkxEMm95M0NOaTU1M3dtMHNKYU1QY1A0RmxYa2wrNzRxYk5ZUnkybmJZS3QzdzVYdTAKcjZtVHVOU2d2VnptK3dHUWo1NCtyczRPWDBIS2dJaStsVWhOc29qbUxXK05ZTTlaODZyWmxvK2c1d0tCZ0VMQQplRXlOSko2c2JCWng2cFo3Vk5hSGhwTm5jdldreDc0WnhiMFM2MWUxL3FwOUNxZ0lXQUR5Q0tkR2tmaCtZN1g2Cjl1TmQzbXdnNGpDUGlvQWVLRnZObVl6K01oVEhjQUlVVVo3dFE1cGxhZnAvRUVZZHRuT2VoV1ArbDFFenV3VlQKWjFEUXU3YnBONHdnb25DUWllOFRJbmoydEZIb29vaTBZUkNJK2lnVkFvR0JBSUxaOXd4WDlnMmVNYU9xUFk1dgo5RGxxNFVEZlpaYkprNFZPbmhjR0pWQUNXbmlpNTU0Y1RCSEkxUTdBT0ZQOHRqK3d3YWJBOWRMaUpDdzJzd0E2ClQrdnhiK1NySGxEUnFON3NNRUQ1Z091REo0eHJxRVdLZ3ZkSEsvME9EMC9ZMUFvSCt2aDlJMHVaV0RRNnNLcXcKeFcrbDk0UTZXSW1xYnpDODZsa3JXa0lCCi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K`
)

var (
	//go:embed testdata/*.json
	testDataFS       embed.FS
	testDataTemplate = template.Must(template.ParseFS(testDataFS, "testdata/*.json"))
)

func testData(t *testing.T, name string, data any) string {
	t.Helper()
	var buf bytes.Buffer
	err := testDataTemplate.ExecuteTemplate(&buf, name, data)
	require.NoError(t, err)
	return buf.String()
}

func TestBuildListeners(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cfg := &config.Config{
		Options: config.NewDefaultOptions(),

		GRPCPort:     "10001",
		HTTPPort:     "10002",
		OutboundPort: "10003",
		MetricsPort:  "10004",
	}
	b := BuilderOptions{
		LocalGRPCAddress:    "local-grpc",
		LocalHTTPAddress:    "local-http",
		LocalMetricsAddress: "local-metrics",
		FileManager:         filemgr.NewManager(),
		ReproxyHandler:      nil,
	}
	t.Run("enable grpc by default", func(t *testing.T) {
		cfg := cfg.Clone()
		lis, err := b.NewForConfig(cfg).BuildListeners(ctx, false)
		assert.NoError(t, err)
		var hasGRPC bool
		for _, li := range lis {
			hasGRPC = hasGRPC || li.Name == "grpc-ingress"
		}
		assert.True(t, hasGRPC, "expected grpc-ingress to be enabled by default")
	})
	t.Run("disable grpc for empty string", func(t *testing.T) {
		cfg := cfg.Clone()
		cfg.Options.GRPCAddr = ""
		lis, err := b.NewForConfig(cfg).BuildListeners(ctx, false)
		assert.NoError(t, err)
		var hasGRPC bool
		for _, li := range lis {
			hasGRPC = hasGRPC || li.Name == "grpc-ingress"
		}
		assert.False(t, hasGRPC, "expected grpc-ingress to be disabled when grpc address is set to the empty string")
	})
}

func Test_buildMetricsHTTPConnectionManagerFilter(t *testing.T) {
	cacheDir, _ := os.UserCacheDir()
	certFileName := filepath.Join(cacheDir, "pomerium", "envoy", "files", "tls-crt-32375a484d4f49594c4d374830.pem")
	keyFileName := filepath.Join(cacheDir, "pomerium", "envoy", "files", "tls-key-33393156483053584631414836.pem")

	b := BuilderOptions{
		LocalGRPCAddress:    "local-grpc",
		LocalHTTPAddress:    "local-http",
		LocalMetricsAddress: "local-metrics",
		FileManager:         filemgr.NewManager(),
		ReproxyHandler:      nil,
	}
	li, err := b.NewForConfig(&config.Config{
		Options: &config.Options{
			MetricsAddr:           "127.0.0.1:9902",
			MetricsCertificate:    aExampleComCert,
			MetricsCertificateKey: aExampleComKey,
		},
	}).buildMetricsListener(context.Background())

	expect := testData(t, "metrics_http_connection_manager.json", struct {
		CertFile, KeyFile string
		EnableReusePort   bool
	}{certFileName, keyFileName, runtime.GOOS == "linux"})
	require.NoError(t, err)
	testutil.AssertProtoJSONEqual(t, expect, li)
}

func Test_buildMainHTTPConnectionManagerFilter(t *testing.T) {
	b := BuilderOptions{
		LocalGRPCAddress:    "local-grpc",
		LocalHTTPAddress:    "local-http",
		LocalMetricsAddress: "local-metrics",
		FileManager:         nil,
		ReproxyHandler:      nil,
	}

	options := config.NewDefaultOptions()
	options.SkipXffAppend = true
	options.XffNumTrustedHops = 1
	options.AuthenticateURLString = "https://authenticate.example.com"
	filter, err := b.NewForConfig(&config.Config{Options: options}).buildMainHTTPConnectionManagerFilter(false)
	require.NoError(t, err)
	testutil.AssertProtoJSONEqual(t, testData(t, "main_http_connection_manager_filter.json", nil), filter)
}

func Test_buildDownstreamTLSContext(t *testing.T) {
	b := BuilderOptions{
		LocalGRPCAddress:    "local-grpc",
		LocalHTTPAddress:    "local-http",
		LocalMetricsAddress: "local-metrics",
		FileManager:         filemgr.NewManager(),
		ReproxyHandler:      nil,
	}

	cacheDir, _ := os.UserCacheDir()
	clientCAFileName := filepath.Join(cacheDir, "pomerium", "envoy", "files", "client-ca-313754424855313435355a5348.pem")

	t.Run("no-validation", func(t *testing.T) {
		downstreamTLSContext, err := b.NewForConfig(&config.Config{Options: &config.Options{}}).buildDownstreamTLSContextMulti(context.Background(), nil)
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
		downstreamTLSContext, err := b.NewForConfig(&config.Config{Options: &config.Options{
			DownstreamMTLS: config.DownstreamMTLSSettings{
				CA: "VEVTVAo=", // "TEST\n" (with a trailing newline)
			},
		}}).buildDownstreamTLSContextMulti(context.Background(), nil)
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
		downstreamTLSContext, err := b.NewForConfig(&config.Config{Options: &config.Options{
			DownstreamMTLS: config.DownstreamMTLSSettings{
				CA:          "VEVTVAo=", // "TEST\n" (with a trailing newline)
				Enforcement: config.MTLSEnforcementRejectConnection,
			},
		}}).buildDownstreamTLSContextMulti(context.Background(), nil)
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
		downstreamTLSContext, err := b.NewForConfig(&config.Config{Options: &config.Options{
			Policies: []config.Policy{
				{
					From:                  "https://a.example.com:1234",
					TLSDownstreamClientCA: "VEVTVA==", // "TEST" (no trailing newline)
				},
			},
		}}).buildDownstreamTLSContextMulti(context.Background(), nil)
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
		downstreamTLSContext, err := b.NewForConfig(config).buildDownstreamTLSContextMulti(context.Background(), nil)
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
		downstreamTLSContext, err = b.NewForConfig(config).buildDownstreamTLSContextMulti(context.Background(), nil)
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
		downstreamTLSContext, err := b.NewForConfig(config).buildDownstreamTLSContextMulti(context.Background(), nil)
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
		downstreamTLSContext, err := b.NewForConfig(&config.Config{Options: &config.Options{
			Cert:      aExampleComCert,
			Key:       aExampleComKey,
			CodecType: config.CodecTypeHTTP1,
		}}).buildDownstreamTLSContextMulti(context.Background(), nil)
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
		downstreamTLSContext, err := b.NewForConfig(&config.Config{Options: &config.Options{
			Cert:      aExampleComCert,
			Key:       aExampleComKey,
			CodecType: config.CodecTypeHTTP2,
		}}).buildDownstreamTLSContextMulti(context.Background(), nil)
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

func Test_getAllDomains(t *testing.T) {
	cert, err := cryptutil.GenerateCertificate(nil, "*.unknown.example.com")
	require.NoError(t, err)
	certPEM, keyPEM, err := cryptutil.EncodeCertificate(cert)
	require.NoError(t, err)

	options := &config.Options{
		Addr:                          "127.0.0.1:9000",
		GRPCAddr:                      "127.0.0.1:9001",
		Services:                      "all",
		AuthenticateURLString:         "https://authenticate.example.com",
		AuthenticateInternalURLString: "https://authenticate.int.example.com",
		AuthorizeURLString:            "https://authorize.example.com:9001",
		DataBrokerURLString:           "https://cache.example.com:9001",
		Policies: []config.Policy{
			{From: "http://a.example.com"},
			{From: "https://b.example.com"},
			{From: "https://c.example.com"},
			{From: "https://d.unknown.example.com"},
		},
		Cert: base64.StdEncoding.EncodeToString(certPEM),
		Key:  base64.StdEncoding.EncodeToString(keyPEM),
	}
	t.Run("routable", func(t *testing.T) {
		t.Run("http", func(t *testing.T) {
			actual, _, err := getAllRouteableHosts(options, "127.0.0.1:9000")
			require.NoError(t, err)
			expect := []string{
				"a.example.com",
				"a.example.com:80",
				"authenticate.example.com",
				"authenticate.example.com:443",
				"authenticate.int.example.com",
				"authenticate.int.example.com:443",
				"b.example.com",
				"b.example.com:443",
				"c.example.com",
				"c.example.com:443",
				"d.unknown.example.com",
				"d.unknown.example.com:443",
			}
			assert.Equal(t, expect, slices.Collect(actual.Items()))
		})
		t.Run("grpc", func(t *testing.T) {
			actual, _, err := getAllRouteableHosts(options, "127.0.0.1:9001")
			require.NoError(t, err)
			expect := []string{
				"authorize.example.com:9001",
				"cache.example.com:9001",
			}
			assert.Equal(t, expect, slices.Collect(actual.Items()))
		})
		t.Run("both", func(t *testing.T) {
			newOptions := *options
			newOptions.GRPCAddr = newOptions.Addr
			actual, _, err := getAllRouteableHosts(&newOptions, "127.0.0.1:9000")
			require.NoError(t, err)
			expect := []string{
				"a.example.com",
				"a.example.com:80",
				"authenticate.example.com",
				"authenticate.example.com:443",
				"authenticate.int.example.com",
				"authenticate.int.example.com:443",
				"authorize.example.com:9001",
				"b.example.com",
				"b.example.com:443",
				"c.example.com",
				"c.example.com:443",
				"cache.example.com:9001",
				"d.unknown.example.com",
				"d.unknown.example.com:443",
			}
			assert.Equal(t, expect, slices.Collect(actual.Items()))
		})
	})

	t.Run("exclude default authenticate", func(t *testing.T) {
		options := config.NewDefaultOptions()
		options.Policies = []config.Policy{
			{From: "https://a.example.com"},
		}
		actual, _, err := getAllRouteableHosts(options, ":443")
		require.NoError(t, err)
		assert.Equal(t, []string{"a.example.com"}, slices.Collect(actual.Items()))
	})
}

func Test_urlMatchesHost(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		sourceURL string
		host      string
		matches   bool
	}{
		{"no port", "http://example.com", "example.com", true},
		{"host http port", "http://example.com", "example.com:80", true},
		{"host https port", "https://example.com", "example.com:443", true},
		{"with port", "https://example.com:443", "example.com:443", true},
		{"url port", "https://example.com:443", "example.com", true},
		{"non standard port", "http://example.com:81", "example.com", false},
		{"non standard host port", "http://example.com:81", "example.com:80", false},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.matches, (&Builder{}).urlMatchesHost(mustParseURL(t, tc.sourceURL), tc.host),
				"urlMatchesHost(%s,%s)", tc.sourceURL, tc.host)
		})
	}
}

func Test_buildRouteConfiguration(t *testing.T) {
	b := BuilderOptions{
		LocalGRPCAddress:    "local-grpc",
		LocalHTTPAddress:    "local-http",
		LocalMetricsAddress: "local-metrics",
		FileManager:         nil,
		ReproxyHandler:      nil,
	}
	virtualHosts := make([]*envoy_config_route_v3.VirtualHost, 10)
	routeConfig, err := b.NewForConfig(&config.Config{}).buildRouteConfiguration("test-route-configuration", virtualHosts)
	require.NoError(t, err)
	assert.Equal(t, "test-route-configuration", routeConfig.GetName())
	assert.Equal(t, virtualHosts, routeConfig.GetVirtualHosts())
	assert.False(t, routeConfig.GetValidateClusters().GetValue())
}

func Test_requireProxyProtocol(t *testing.T) {
	b := BuilderOptions{
		LocalGRPCAddress:    "local-grpc",
		LocalHTTPAddress:    "local-http",
		LocalMetricsAddress: "local-metrics",
		FileManager:         nil,
		ReproxyHandler:      nil,
	}
	t.Run("required", func(t *testing.T) {
		li, err := b.NewForConfig(&config.Config{Options: &config.Options{
			UseProxyProtocol: true,
			InsecureServer:   true,
		}}).buildMainListener(context.Background(), false)
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, `[
			{
				"name": "envoy.filters.listener.proxy_protocol",
				"typedConfig": {
					"@type": "type.googleapis.com/envoy.extensions.filters.listener.proxy_protocol.v3.ProxyProtocol"
				}
			}
		]`, li.GetListenerFilters())
	})
	t.Run("not required", func(t *testing.T) {
		li, err := b.NewForConfig(&config.Config{Options: &config.Options{
			UseProxyProtocol: false,
			InsecureServer:   true,
		}}).buildMainListener(context.Background(), false)
		require.NoError(t, err)
		assert.Len(t, li.GetListenerFilters(), 0)
	})
}
