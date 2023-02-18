package envoyconfig

import (
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"os"
	"path/filepath"
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

func testData(t *testing.T, name string, data interface{}) string {
	t.Helper()
	var buf bytes.Buffer
	err := testDataTemplate.ExecuteTemplate(&buf, name, data)
	require.NoError(t, err)
	return buf.String()
}

func Test_buildMetricsHTTPConnectionManagerFilter(t *testing.T) {
	cacheDir, _ := os.UserCacheDir()
	certFileName := filepath.Join(cacheDir, "pomerium", "envoy", "files", "tls-crt-354e49305a5a39414a545530374e58454e48334148524c4e324258463837364355564c4e4532464b54355139495547514a38.pem")
	keyFileName := filepath.Join(cacheDir, "pomerium", "envoy", "files", "tls-key-3350415a38414e4e4a4655424e55393430474147324651433949384e485341334b5157364f424b4c5856365a545937383735.pem")

	b := New("local-grpc", "local-http", "local-metrics", filemgr.NewManager(), nil)
	li, err := b.buildMetricsListener(&config.Config{
		Options: &config.Options{
			MetricsAddr:           "127.0.0.1:9902",
			MetricsCertificate:    aExampleComCert,
			MetricsCertificateKey: aExampleComKey,
		},
	})

	expect := testData(t, "metrics_http_connection_manager.json", struct{ CertFile, KeyFile string }{certFileName, keyFileName})
	require.NoError(t, err)
	testutil.AssertProtoJSONEqual(t, expect, li)
}

func Test_buildMainHTTPConnectionManagerFilter(t *testing.T) {
	b := New("local-grpc", "local-http", "local-metrics", nil, nil)

	options := config.NewDefaultOptions()
	options.SkipXffAppend = true
	options.XffNumTrustedHops = 1
	options.AuthenticateURLString = "https://authenticate.example.com"
	filter, err := b.buildMainHTTPConnectionManagerFilter(options)
	require.NoError(t, err)
	testutil.AssertProtoJSONEqual(t, testData(t, "main_http_connection_manager_filter.json", nil), filter)
}

func Test_buildDownstreamTLSContext(t *testing.T) {
	b := New("local-grpc", "local-http", "local-metrics", filemgr.NewManager(), nil)

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
					"tlsMinimumProtocolVersion": "TLSv1_2"
				},
				"alpnProtocols": ["h2", "http/1.1"],
				"validationContext": {
					"trustChainVerification": "ACCEPT_UNTRUSTED"
				}
			}
		}`, downstreamTLSContext)
	})
	t.Run("client-ca", func(t *testing.T) {
		downstreamTLSContext, err := b.buildDownstreamTLSContextMulti(context.Background(), &config.Config{Options: &config.Options{
			ClientCA: "TEST",
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
					"tlsMinimumProtocolVersion": "TLSv1_2"
				},
				"alpnProtocols": ["h2", "http/1.1"],
				"validationContext": {
					"trustChainVerification": "ACCEPT_UNTRUSTED"
				}
			}
		}`, downstreamTLSContext)
	})
	t.Run("policy-client-ca", func(t *testing.T) {
		downstreamTLSContext, err := b.buildDownstreamTLSContextMulti(context.Background(), &config.Config{Options: &config.Options{
			Policies: []config.Policy{
				{
					Source:                &config.StringURL{URL: mustParseURL(t, "https://a.example.com:1234")},
					TLSDownstreamClientCA: "TEST",
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
					"tlsMinimumProtocolVersion": "TLSv1_2"
				},
				"alpnProtocols": ["h2", "http/1.1"],
				"validationContext": {
					"trustChainVerification": "ACCEPT_UNTRUSTED"
				}
			}
		}`, downstreamTLSContext)
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
					"tlsMinimumProtocolVersion": "TLSv1_2"
				},
				"alpnProtocols": ["http/1.1"],
				"validationContext": {
					"trustChainVerification": "ACCEPT_UNTRUSTED"
				}
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
					"tlsMinimumProtocolVersion": "TLSv1_2"
				},
				"alpnProtocols": ["h2"],
				"validationContext": {
					"trustChainVerification": "ACCEPT_UNTRUSTED"
				}
			}
		}`, downstreamTLSContext)
	})
}

func Test_getAllDomains(t *testing.T) {
	cert, err := cryptutil.GenerateCertificate(nil, "*.unknown.example.com")
	require.NoError(t, err)
	certPEM, keyPEM, err := cryptutil.EncodeCertificate(cert)
	require.NoError(t, err)

	options := &config.Options{
		Addr:                  "127.0.0.1:9000",
		GRPCAddr:              "127.0.0.1:9001",
		Services:              "all",
		AuthenticateURLString: "https://authenticate.example.com",
		AuthorizeURLString:    "https://authorize.example.com:9001",
		DataBrokerURLString:   "https://cache.example.com:9001",
		Policies: []config.Policy{
			{Source: &config.StringURL{URL: mustParseURL(t, "http://a.example.com")}},
			{Source: &config.StringURL{URL: mustParseURL(t, "https://b.example.com")}},
			{Source: &config.StringURL{URL: mustParseURL(t, "https://c.example.com")}},
			{Source: &config.StringURL{URL: mustParseURL(t, "https://d.unknown.example.com")}},
		},
		Cert: base64.StdEncoding.EncodeToString(certPEM),
		Key:  base64.StdEncoding.EncodeToString(keyPEM),
	}
	t.Run("routable", func(t *testing.T) {
		t.Run("http", func(t *testing.T) {
			actual, err := getAllRouteableHosts(options, "127.0.0.1:9000")
			require.NoError(t, err)
			expect := []string{
				"a.example.com",
				"a.example.com:80",
				"authenticate.example.com",
				"authenticate.example.com:443",
				"b.example.com",
				"b.example.com:443",
				"c.example.com",
				"c.example.com:443",
				"d.unknown.example.com",
				"d.unknown.example.com:443",
			}
			assert.Equal(t, expect, actual)
		})
		t.Run("grpc", func(t *testing.T) {
			actual, err := getAllRouteableHosts(options, "127.0.0.1:9001")
			require.NoError(t, err)
			expect := []string{
				"authorize.example.com:9001",
				"cache.example.com:9001",
			}
			assert.Equal(t, expect, actual)
		})
		t.Run("both", func(t *testing.T) {
			newOptions := *options
			newOptions.GRPCAddr = newOptions.Addr
			actual, err := getAllRouteableHosts(&newOptions, "127.0.0.1:9000")
			require.NoError(t, err)
			expect := []string{
				"a.example.com",
				"a.example.com:80",
				"authenticate.example.com",
				"authenticate.example.com:443",
				"authorize.example.com:9001",
				"b.example.com",
				"b.example.com:443",
				"c.example.com",
				"c.example.com:443",
				"cache.example.com:9001",
				"d.unknown.example.com",
				"d.unknown.example.com:443",
			}
			assert.Equal(t, expect, actual)
		})
	})
	t.Run("tls", func(t *testing.T) {
		t.Run("http", func(t *testing.T) {
			actual, err := getAllServerNames(&config.Config{Options: options}, "127.0.0.1:9000")
			require.NoError(t, err)
			expect := []string{
				"*",
				"*.unknown.example.com",
				"a.example.com",
				"authenticate.example.com",
				"b.example.com",
				"c.example.com",
				"d.unknown.example.com",
			}
			assert.Equal(t, expect, actual)
		})
		t.Run("grpc", func(t *testing.T) {
			actual, err := getAllServerNames(&config.Config{Options: options}, "127.0.0.1:9001")
			require.NoError(t, err)
			expect := []string{
				"*",
				"*.unknown.example.com",
				"authorize.example.com",
				"cache.example.com",
			}
			assert.Equal(t, expect, actual)
		})
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

			assert.Equal(t, tc.matches, urlMatchesHost(mustParseURL(t, tc.sourceURL), tc.host),
				"urlMatchesHost(%s,%s)", tc.sourceURL, tc.host)
		})
	}
}

func Test_buildRouteConfiguration(t *testing.T) {
	b := New("local-grpc", "local-http", "local-metrics", nil, nil)
	virtualHosts := make([]*envoy_config_route_v3.VirtualHost, 10)
	routeConfig, err := b.buildRouteConfiguration("test-route-configuration", virtualHosts)
	require.NoError(t, err)
	assert.Equal(t, "test-route-configuration", routeConfig.GetName())
	assert.Equal(t, virtualHosts, routeConfig.GetVirtualHosts())
	assert.False(t, routeConfig.GetValidateClusters().GetValue())
}

func Test_requireProxyProtocol(t *testing.T) {
	b := New("local-grpc", "local-http", "local-metrics", nil, nil)
	t.Run("required", func(t *testing.T) {
		li, err := b.buildMainListener(context.Background(), &config.Config{Options: &config.Options{
			UseProxyProtocol: true,
			InsecureServer:   true,
		}})
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
		li, err := b.buildMainListener(context.Background(), &config.Config{Options: &config.Options{
			UseProxyProtocol: false,
			InsecureServer:   true,
		}})
		require.NoError(t, err)
		assert.Len(t, li.GetListenerFilters(), 0)
	})
}
