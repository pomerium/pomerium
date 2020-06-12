package controlplane

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/testutil"
)

const (
	aExampleComCert = `LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVQVENDQXFXZ0F3SUJBZ0lSQUlWMDhHSVFYTWRVT0NXV3FocXlGR3N3RFFZSktvWklodmNOQVFFTEJRQXcKY3pFZU1Cd0dBMVVFQ2hNVmJXdGpaWEowSUdSbGRtVnNiM0J0Wlc1MElFTkJNU1F3SWdZRFZRUUxEQnRqWVd4bApZa0J3YjNBdGIzTWdLRU5oYkdWaUlFUnZlSE5sZVNreEt6QXBCZ05WQkFNTUltMXJZMlZ5ZENCallXeGxZa0J3CmIzQXRiM01nS0VOaGJHVmlJRVJ2ZUhObGVTa3dIaGNOTVRrd05qQXhNREF3TURBd1doY05NekF3TlRJeU1qRXoKT0RRMFdqQlBNU2N3SlFZRFZRUUtFeDV0YTJObGNuUWdaR1YyWld4dmNHMWxiblFnWTJWeWRHbG1hV05oZEdVeApKREFpQmdOVkJBc01HMk5oYkdWaVFIQnZjQzF2Y3lBb1EyRnNaV0lnUkc5NGMyVjVLVENDQVNJd0RRWUpLb1pJCmh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTm1HMWFKaXc0L29SMHFqUDMxUjRXeTZkOUVqZHc5K1kyelQKcjBDbGNYTDYxRk11R0YrKzJRclV6Y0VUZlZ2dGM1OXNQa0xkRHNtZ0Y2VlZCOTkyQ3ArWDlicWczWmQwSXZtbApVbjJvdTM5eUNEYnV2Q0E2d1gwbGNHL2JkRDE3TkRrS0poL3g5SDMzU3h4SG5UamlKdFBhbmt1MUI3ajdtRmM5Ck5jNXRyamFvUHBGaFJqMTJ1L0dWajRhWWs3SStpWHRpZHBjZXp2eWNDT0NtQlIwNHkzeWx5Q2sxSWNMTUhWOEEKNXphUFpVck15ZUtnTE1PTGlDSDBPeHhhUzh0Nk5vTjZudDdmOUp1TUxTN2V5SkxkQW05bGg0c092YXBPVklXZgpJQitaYnk5bkQ1dWl4N3V0a3llWTFOeE05SFZhUmZTQzcrejM4TDBWN3lJZlpCNkFLcWNDQXdFQUFhTndNRzR3CkRnWURWUjBQQVFIL0JBUURBZ1dnTUJNR0ExVWRKUVFNTUFvR0NDc0dBUVVGQndNQk1Bd0dBMVVkRXdFQi93UUMKTUFBd0h3WURWUjBqQkJnd0ZvQVVTaG9mWE5rY1hoMnE0d25uV1oyYmNvMjRYRVF3R0FZRFZSMFJCQkV3RDRJTgpZUzVsZUdGdGNHeGxMbU52YlRBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVlFQVA3aHVraThGeG54azRoVnJYUk93Ck51Uy9OUFhmQ3VaVDZWemJYUVUxbWNrZmhweVNDajVRZkFDQzdodVp6Qkp0NEtsUHViWHdRQ25YMFRMSmg1L0cKUzZBWEFXQ3VTSW5jTTZxNGs4MFAzVllWK3hXOS9rdERnTk1FTlNxSjdKR3lqdzBWWHlhOUZwdWd6Q3ZnN290RQo5STcrZTN0cmJnUDBHY3plSml6WTJBMVBWU082MVdKQ1lNQjNDLzcwVE9KMkZTNy82bURPTG9DSVJCY215cW5KClY2Vk5sRDl3Y2xmUWIrZUp0YlY0Vlg2RUY5UEYybUtncUNKT0FKLzBoMHAydTBhZGgzMkJDS2dIMDRSYUtuSS8KUzY1N0MrN1YzVEgzQ1VIVHgrdDRRRll4UEhRL0loQ3pYdUpVeFQzYWtYNEQ1czJkTHp2RnBJMFIzTVBwUE9VQQpUelpSdDI2T3FVNHlUdUFnb0kvZnZMdk55VTNZekF3ZUQ2Mndxc1hiVHAranNFcWpoODUvakpXWnA4RExKK0w3CmhXQW0rSVNKTzhrNWgwR0lIMFllb01heXBJbjRubWVsbHNSM1dvYzZRVTZ4cFFTd3V1NXE0ckJzOUxDWS9kZkwKNkEzMEhlYXVVK2sydGFUVlBMY2FCZm11NDJPaHMyYzQ0bzNPYnlvVkNDNi8KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=`
	aExampleComKey  = `LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktnd2dnU2tBZ0VBQW9JQkFRRFpodFdpWXNPUDZFZEsKb3o5OVVlRnN1bmZSSTNjUGZtTnMwNjlBcFhGeSt0UlRMaGhmdnRrSzFNM0JFMzFiN1hPZmJENUMzUTdKb0JlbApWUWZmZGdxZmwvVzZvTjJYZENMNXBWSjlxTHQvY2dnMjdyd2dPc0Y5SlhCdjIzUTllelE1Q2lZZjhmUjk5MHNjClI1MDQ0aWJUMnA1THRRZTQrNWhYUFRYT2JhNDJxRDZSWVVZOWRydnhsWStHbUpPeVBvbDdZbmFYSHM3OG5BamcKcGdVZE9NdDhwY2dwTlNIQ3pCMWZBT2MyajJWS3pNbmlvQ3pEaTRnaDlEc2NXa3ZMZWphRGVwN2UzL1NiakMwdQozc2lTM1FKdlpZZUxEcjJxVGxTRm55QWZtVzh2WncrYm9zZTdyWk1ubU5UY1RQUjFXa1gwZ3UvczkvQzlGZThpCkgyUWVnQ3FuQWdNQkFBRUNnZ0VCQUsrclFrLzNyck5EQkgvMFFrdTBtbll5U0p6dkpUR3dBaDlhL01jYVZQcGsKTXFCU000RHZJVnlyNnRZb0pTN2VIbWY3QkhUL0RQZ3JmNjBYZEZvMGUvUFN4ckhIUSswUjcwVHBEQ3RLM3REWAppR2JFZWMwVlpqam95VnFzUWIxOUIvbWdocFY1MHRiL3BQcmJvczdUWkVQbTQ3dUVJUTUwc055VEpDYm5VSy8xCnhla2ZmZ3hMbmZlRUxoaXhDNE1XYjMzWG9GNU5VdWduQ2pUakthUFNNUmpISm9YSFlGWjdZdEdlSEd1aDR2UGwKOU5TM0YxT2l0MWNnQzNCSm1BM28yZmhYbTRGR1FhQzNjYUdXTzE5eHAwRWE1eXQ0RHZOTWp5WlgvSkx1Qko0NQpsZU5jUSs3c3U0dW0vY0hqcFFVenlvZmoydFBIU085QXczWGY0L2lmN0hFQ2dZRUE1SWMzMzVKUUhJVlQwc003CnhkY3haYmppbUE5alBWMDFXSXh0di8zbzFJWm5TUGFocEFuYXVwZGZqRkhKZmJTYlZXaUJTaUZpb2RTR3pIdDgKTlZNTGFyVzVreDl5N1luYXdnZjJuQjc2VG03aFl6L3h5T3AxNXFRbmswVW9DdnQ2MHp6dDl5UE5KQ1pWalFwNgp4cUw4T1c4emNlUGpxZzJBTHRtcVhpNitZRXNDZ1lFQTg2ME5zSHMzNktFZE91Q1o1TXF6NVRLSmVYSzQ5ZkdBCjdxcjM5Sm9RcWYzbEhSSWozUlFlNERkWmQ5NUFXcFRKUEJXdnp6NVROOWdwNHVnb3VGc0tCaG82YWtsUEZTUFIKRkZwWCtGZE56eHJGTlAwZHhydmN0bXU2OW91MFR0QU1jd1hYWFJuR1BuK0xDTnVUUHZndHZTTnRwSEZMb0dzUQorVDFpTjhpWS9aVUNnWUJpMVJQVjdkb1ZxNWVuNCtWYTE0azJlL0lMWDBSRkNxV0NpU0VCMGxhNmF2SUtQUmVFCjhQb1dqbGExUWIzSlRxMkxEMm95M0NOaTU1M3dtMHNKYU1QY1A0RmxYa2wrNzRxYk5ZUnkybmJZS3QzdzVYdTAKcjZtVHVOU2d2VnptK3dHUWo1NCtyczRPWDBIS2dJaStsVWhOc29qbUxXK05ZTTlaODZyWmxvK2c1d0tCZ0VMQQplRXlOSko2c2JCWng2cFo3Vk5hSGhwTm5jdldreDc0WnhiMFM2MWUxL3FwOUNxZ0lXQUR5Q0tkR2tmaCtZN1g2Cjl1TmQzbXdnNGpDUGlvQWVLRnZObVl6K01oVEhjQUlVVVo3dFE1cGxhZnAvRUVZZHRuT2VoV1ArbDFFenV3VlQKWjFEUXU3YnBONHdnb25DUWllOFRJbmoydEZIb29vaTBZUkNJK2lnVkFvR0JBSUxaOXd4WDlnMmVNYU9xUFk1dgo5RGxxNFVEZlpaYkprNFZPbmhjR0pWQUNXbmlpNTU0Y1RCSEkxUTdBT0ZQOHRqK3d3YWJBOWRMaUpDdzJzd0E2ClQrdnhiK1NySGxEUnFON3NNRUQ1Z091REo0eHJxRVdLZ3ZkSEsvME9EMC9ZMUFvSCt2aDlJMHVaV0RRNnNLcXcKeFcrbDk0UTZXSW1xYnpDODZsa3JXa0lCCi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K`
)

func Test_buildMainHTTPConnectionManagerFilter(t *testing.T) {
	options := config.NewDefaultOptions()
	filter := buildMainHTTPConnectionManagerFilter(options, []string{"example.com"})
	testutil.AssertProtoJSONEqual(t, `{
		"name": "envoy.filters.network.http_connection_manager",
		"typedConfig": {
			"@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
			"accessLog": [{
				"name": "envoy.access_loggers.http_grpc",
				"typedConfig": {
					"@type": "type.googleapis.com/envoy.extensions.access_loggers.grpc.v3.HttpGrpcAccessLogConfig",
					"commonConfig": {
						"grpcService": {
							"envoyGrpc": {
								"clusterName": "pomerium-control-plane-grpc"
							}
						},
						"logName": "ingress-http"
					}
				}
			}],
			"commonHttpProtocolOptions": {
				"idleTimeout": "300s"
			},
			"httpFilters": [
				{
					"name": "envoy.filters.http.ext_authz",
					"typedConfig": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz",
						"grpcService": {
							"envoyGrpc": {
								"clusterName": "pomerium-authz"
							},
							"timeout": "10s"
						},
						"includePeerCertificate": true,
						"statusOnError": {
							"code": "InternalServerError"
						}
					}
				},
				{
					"name": "envoy.filters.http.lua",
					"typedConfig": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua",
						"inlineCode": "function envoy_on_request(request_handle)\n    local headers = request_handle:headers()\n    local dynamic_meta = request_handle:streamInfo():dynamicMetadata()\n    if headers:get(\"x-pomerium-set-cookie\") ~= nil then\n        dynamic_meta:set(\"envoy.filters.http.lua\", \"pomerium_set_cookie\",\n                         headers:get(\"x-pomerium-set-cookie\"))\n        headers:remove(\"x-pomerium-set-cookie\")\n    end\nend\n\nfunction envoy_on_response(response_handle)\n    local headers = response_handle:headers()\n    local dynamic_meta = response_handle:streamInfo():dynamicMetadata()\n    local tbl = dynamic_meta:get(\"envoy.filters.http.lua\")\n    if tbl ~= nil and tbl[\"pomerium_set_cookie\"] ~= nil then\n        headers:add(\"set-cookie\", tbl[\"pomerium_set_cookie\"])\n    end\nend\n"
					}
				},
				{
					"name": "envoy.filters.http.lua",
					"typedConfig": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua",
						"inlineCode": "function remove_pomerium_cookie(cookie_name, cookie)\n    -- lua doesn't support optional capture groups\n    -- so we replace twice to handle pomerium=xyz at the end of the string\n    cookie = cookie:gsub(cookie_name .. \"=[^;]+; \", \"\")\n    cookie = cookie:gsub(cookie_name .. \"=[^;]+\", \"\")\n    return cookie\nend\n\nfunction has_prefix(str, prefix)\n    return str ~= nil and str:sub(1, #prefix) == prefix\nend\n\nfunction envoy_on_request(request_handle)\n    local headers = request_handle:headers()\n    local metadata = request_handle:metadata()\n\n    local remove_cookie_name = metadata:get(\"remove_pomerium_cookie\")\n    if remove_cookie_name then\n        local cookie = headers:get(\"cookie\")\n        if cookie ~= nil then\n            newcookie = remove_pomerium_cookie(remove_cookie_name, cookie)\n            headers:replace(\"cookie\", newcookie)\n        end\n    end\n\n    local remove_authorization = metadata:get(\"remove_pomerium_authorization\")\n    if remove_authorization then\n        local authorization = headers:get(\"authorization\")\n        local authorization_prefix = \"Pomerium \"\n        if has_prefix(authorization, authorization_prefix) then\n            headers:remove(\"authorization\")\n        end\n    end\nend\n\nfunction envoy_on_response(response_handle)\n\nend\n"
					}
				},
				{
					"name": "envoy.filters.http.router"
				}
			],
			"requestTimeout": "30s",
			"routeConfig": {
				"name": "main",
				"virtualHosts": [
					{
						"name": "example.com",
						"domains": ["example.com"],
						"routes": [
							{
								"name": "pomerium-path-/ping",
								"match": {
									"path": "/ping"
								},
								"route": {
									"cluster": "pomerium-control-plane-http"
								},
								"typedPerFilterConfig": {
									"envoy.filters.http.ext_authz": {
										"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
										"disabled": true
									}
								}
							},
							{
								"name": "pomerium-path-/healthz",
								"match": {
									"path": "/healthz"
								},
								"route": {
									"cluster": "pomerium-control-plane-http"
								},
								"typedPerFilterConfig": {
									"envoy.filters.http.ext_authz": {
										"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
										"disabled": true
									}
								}
							},
							{
								"name": "pomerium-path-/.pomerium",
								"match": {
									"path": "/.pomerium"
								},
								"route": {
									"cluster": "pomerium-control-plane-http"
								},
								"typedPerFilterConfig": {
									"envoy.filters.http.ext_authz": {
										"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
										"disabled": true
									}
								}
							},
							{
								"name": "pomerium-prefix-/.pomerium/",
								"match": {
									"prefix": "/.pomerium/"
								},
								"route": {
									"cluster": "pomerium-control-plane-http"
								},
								"typedPerFilterConfig": {
									"envoy.filters.http.ext_authz": {
										"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
										"disabled": true
									}
								}
							},
							{
								"name": "pomerium-path-/.well-known/pomerium",
								"match": {
									"path": "/.well-known/pomerium"
								},
								"route": {
									"cluster": "pomerium-control-plane-http"
								},
								"typedPerFilterConfig": {
									"envoy.filters.http.ext_authz": {
										"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
										"disabled": true
									}
								}
							},
							{
								"name": "pomerium-prefix-/.well-known/pomerium/",
								"match": {
									"prefix": "/.well-known/pomerium/"
								},
								"route": {
									"cluster": "pomerium-control-plane-http"
								},
								"typedPerFilterConfig": {
									"envoy.filters.http.ext_authz": {
										"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
										"disabled": true
									}
								}
							}
						]
					},
					{
						"name": "catch-all",
						"domains": ["*"],
						"routes": [
							{
								"name": "pomerium-path-/ping",
								"match": {
									"path": "/ping"
								},
								"route": {
									"cluster": "pomerium-control-plane-http"
								},
								"typedPerFilterConfig": {
									"envoy.filters.http.ext_authz": {
										"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
										"disabled": true
									}
								}
							},
							{
								"name": "pomerium-path-/healthz",
								"match": {
									"path": "/healthz"
								},
								"route": {
									"cluster": "pomerium-control-plane-http"
								},
								"typedPerFilterConfig": {
									"envoy.filters.http.ext_authz": {
										"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
										"disabled": true
									}
								}
							},
							{
								"name": "pomerium-path-/.pomerium",
								"match": {
									"path": "/.pomerium"
								},
								"route": {
									"cluster": "pomerium-control-plane-http"
								},
								"typedPerFilterConfig": {
									"envoy.filters.http.ext_authz": {
										"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
										"disabled": true
									}
								}
							},
							{
								"name": "pomerium-prefix-/.pomerium/",
								"match": {
									"prefix": "/.pomerium/"
								},
								"route": {
									"cluster": "pomerium-control-plane-http"
								},
								"typedPerFilterConfig": {
									"envoy.filters.http.ext_authz": {
										"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
										"disabled": true
									}
								}
							},
							{
								"name": "pomerium-path-/.well-known/pomerium",
								"match": {
									"path": "/.well-known/pomerium"
								},
								"route": {
									"cluster": "pomerium-control-plane-http"
								},
								"typedPerFilterConfig": {
									"envoy.filters.http.ext_authz": {
										"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
										"disabled": true
									}
								}
							},
							{
								"name": "pomerium-prefix-/.well-known/pomerium/",
								"match": {
									"prefix": "/.well-known/pomerium/"
								},
								"route": {
									"cluster": "pomerium-control-plane-http"
								},
								"typedPerFilterConfig": {
									"envoy.filters.http.ext_authz": {
										"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
										"disabled": true
									}
								}
							}
						]
					}
				],
				"validateClusters": false
			},
			"statPrefix": "ingress",
			"tracing": {
				"randomSampling": {
					"value": 0.01
				}
			}
		}
	}`, filter)
}

func Test_buildDownstreamTLSContext(t *testing.T) {
	certA, err := cryptutil.CertificateFromBase64(aExampleComCert, aExampleComKey)
	if !assert.NoError(t, err) {
		return
	}

	downstreamTLSContext := buildDownstreamTLSContext(&config.Options{
		Certificates: []tls.Certificate{*certA},
	}, "a.example.com")

	cacheDir, _ := os.UserCacheDir()
	certFileName := filepath.Join(cacheDir, "pomerium", "envoy", "files", "tls-crt-921a8294d2e2ec54.pem")
	keyFileName := filepath.Join(cacheDir, "pomerium", "envoy", "files", "tls-key-d5cf35b1e8533e4a.pem")

	testutil.AssertProtoJSONEqual(t, `{
		"commonTlsContext": {
			"tlsParams": {
				"tlsMinimumProtocolVersion": "TLSv1_2"
			},
			"alpnProtocols": ["h2", "http/1.1"],
			"tlsCertificates": [
				{
					"certificateChain": {
						"filename": "`+certFileName+`"
					},
					"privateKey": {
						"filename": "`+keyFileName+`"
					}
				}
			]
		}
	}`, downstreamTLSContext)
}

func Test_getAllRouteableDomains(t *testing.T) {
	options := &config.Options{
		Addr:            "127.0.0.1:9000",
		GRPCAddr:        "127.0.0.1:9001",
		Services:        "all",
		AuthenticateURL: mustParseURL("https://authenticate.example.com"),
		AuthorizeURL:    mustParseURL("https://authorize.example.com:9001"),
		CacheURL:        mustParseURL("https://cache.example.com:9001"),
		Policies: []config.Policy{
			{Source: &config.StringURL{URL: mustParseURL("https://a.example.com")}},
			{Source: &config.StringURL{URL: mustParseURL("https://b.example.com")}},
			{Source: &config.StringURL{URL: mustParseURL("https://c.example.com")}},
		},
	}
	t.Run("http", func(t *testing.T) {
		actual := getAllRouteableDomains(options, "127.0.0.1:9000")
		expect := []string{
			"a.example.com",
			"authenticate.example.com",
			"b.example.com",
			"c.example.com",
		}
		assert.Equal(t, expect, actual)
	})
	t.Run("grpc", func(t *testing.T) {
		actual := getAllRouteableDomains(options, "127.0.0.1:9001")
		expect := []string{
			"authorize.example.com:9001",
			"cache.example.com:9001",
		}
		assert.Equal(t, expect, actual)
	})
}

func Test_buildRouteConfiguration(t *testing.T) {
	virtualHosts := make([]*envoy_config_route_v3.VirtualHost, 10)
	routeConfig := buildRouteConfiguration("test-route-configuration", virtualHosts)
	assert.Equal(t, "test-route-configuration", routeConfig.GetName())
	assert.Equal(t, virtualHosts, routeConfig.GetVirtualHosts())
	assert.False(t, routeConfig.GetValidateClusters().GetValue())
}
