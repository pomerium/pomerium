package envoyconfig

import (
	"bytes"
	"context"
	"embed"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/testutil"
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
	b := New("local-grpc", "local-http", "local-metrics", filemgr.NewManager(), nil)
	t.Run("enable grpc by default", func(t *testing.T) {
		cfg := cfg.Clone()
		lis, err := b.BuildListeners(ctx, cfg, false)
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
		lis, err := b.BuildListeners(ctx, cfg, false)
		assert.NoError(t, err)
		var hasGRPC bool
		for _, li := range lis {
			hasGRPC = hasGRPC || li.Name == "grpc-ingress"
		}
		assert.False(t, hasGRPC, "expected grpc-ingress to be disabled when grpc address is set to the empty string")
	})
	t.Run("quic", func(t *testing.T) {
		t.Parallel()

		cfg := cfg.Clone()
		cfg.Options.CodecType = config.CodecTypeHTTP3
		lis, err := b.BuildListeners(ctx, cfg, false)
		assert.NoError(t, err)

		var hasHTTPS, hasQUIC bool
		for _, li := range lis {
			switch li.GetName() {
			case "https-ingress":
				hasHTTPS = true
				httpConfig := gjson.Get(protojson.Format(li), "filterChains.1.filters.0.typedConfig")
				assert.Equal(t, "", httpConfig.Get("codecType").String())
				assert.JSONEq(t, `{
					"name": "envoy.filters.http.header_mutation",
					"typedConfig": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.header_mutation.v3.HeaderMutation",
						"mutations": {
							"responseMutations": [{
								"append": {
									"header": {
										"key": "alt-svc",
										"value": "h3=\":443\"; ma=86400"
									}
								}
							}]
						}
					}
				}`, httpConfig.Get("httpFilters.6").String(),
					"should add alt-svc header")
			case "quic-ingress":
				hasQUIC = true
				httpConfig := gjson.Get(protojson.Format(li), "filterChains.0.filters.0.typedConfig")
				assert.Equal(t, "HTTP3", httpConfig.Get("codecType").String())
				assert.JSONEq(t, `{
					"allowExtendedConnect": true
				}`, httpConfig.Get("http3ProtocolOptions").String())
			}
		}

		assert.True(t, hasHTTPS, "should have https-ingress listener")
		assert.True(t, hasQUIC, "should have quic-ingress listener")
	})
}

func Test_buildMetricsHTTPConnectionManagerFilter(t *testing.T) {
	cacheDir, _ := os.UserCacheDir()
	certFileName := filepath.Join(cacheDir, "pomerium", "envoy", "files", "tls-crt-32375a484d4f49594c4d374830.pem")
	keyFileName := filepath.Join(cacheDir, "pomerium", "envoy", "files", "tls-key-33393156483053584631414836.pem")

	b := New("local-grpc", "local-http", "local-metrics", filemgr.NewManager(), nil)
	li, err := b.buildMetricsListener(&config.Config{
		Options: &config.Options{
			MetricsAddr:           "127.0.0.1:9902",
			MetricsCertificate:    aExampleComCert,
			MetricsCertificateKey: aExampleComKey,
		},
	})

	expect := testData(t, "metrics_http_connection_manager.json", struct {
		CertFile, KeyFile string
		EnableReusePort   bool
	}{certFileName, keyFileName, runtime.GOOS == "linux"})
	require.NoError(t, err)
	testutil.AssertProtoJSONEqual(t, expect, li)
}

func Test_buildMainHTTPConnectionManagerFilter(t *testing.T) {
	b := New("local-grpc", "local-http", "local-metrics", nil, nil)

	options := config.NewDefaultOptions()
	options.SkipXffAppend = true
	options.XffNumTrustedHops = 1
	options.AuthenticateURLString = "https://authenticate.example.com"
	options.TracingProvider = "otlp"
	filter, err := b.buildMainHTTPConnectionManagerFilter(context.Background(), &config.Config{Options: options}, false, false)
	require.NoError(t, err)

	testutil.AssertProtoJSONEqual(t, testData(t, "main_http_connection_manager_filter.json", nil), filter)
}
