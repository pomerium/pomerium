package envoyconfig

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/internal/urlutil"
)

func policyNameFunc() func(*config.Policy) string {
	i := 0
	return func(*config.Policy) string {
		i++
		return fmt.Sprintf("policy-%d", i)
	}
}

func Test_buildGRPCRoutes(t *testing.T) {
	b := &Builder{filemgr: filemgr.NewManager()}
	routes, err := b.buildGRPCRoutes()
	require.NoError(t, err)
	testutil.AssertProtoJSONEqual(t, `
		[
			{
				"name": "pomerium-grpc",
				"match": {
					"grpc": {},
					"prefix": "/"
				},
				"route": {
					"cluster": "pomerium-control-plane-grpc"
				},
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"disabled": true
					}
				}
			}
		]
	`, routes)
}

func Test_buildPomeriumHTTPRoutes(t *testing.T) {
	b := &Builder{filemgr: filemgr.NewManager()}
	routeString := func(typ, name string, protected bool) string {
		str := `{
				"name": "pomerium-` + typ + `-` + name + `",
				"match": {
					"` + typ + `": "` + name + `"
				},
				"route": {
					"cluster": "pomerium-control-plane-http"
				}
			`
		if !protected {
			str += `,
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"disabled": true
					}
				}
			`
		}
		str += "}"
		return str
	}
	t.Run("authenticate", func(t *testing.T) {
		options := &config.Options{
			Services:                 "all",
			AuthenticateURLString:    "https://authenticate.example.com",
			AuthenticateCallbackPath: "/oauth2/callback",
		}
		routes, err := b.buildPomeriumHTTPRoutes(options, "authenticate.example.com")
		require.NoError(t, err)

		testutil.AssertProtoJSONEqual(t, `[
			`+routeString("path", "/.pomerium/jwt", true)+`,
			`+routeString("path", urlutil.WebAuthnURLPath, true)+`,
			`+routeString("path", "/ping", false)+`,
			`+routeString("path", "/healthz", false)+`,
			`+routeString("path", "/.pomerium", false)+`,
			`+routeString("prefix", "/.pomerium/", false)+`,
			`+routeString("path", "/.well-known/pomerium", false)+`,
			`+routeString("prefix", "/.well-known/pomerium/", false)+`,
			`+routeString("path", "/robots.txt", false)+`,
			`+routeString("path", "/oauth2/callback", false)+`,
			`+routeString("path", "/", false)+`
		]`, routes)
	})
	t.Run("proxy fronting authenticate", func(t *testing.T) {
		options := &config.Options{
			Services:                 "proxy",
			AuthenticateURLString:    "https://authenticate.example.com",
			AuthenticateCallbackPath: "/oauth2/callback",
		}
		routes, err := b.buildPomeriumHTTPRoutes(options, "authenticate.example.com")
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, "null", routes)
	})

	t.Run("with robots", func(t *testing.T) {
		options := &config.Options{
			Services:                 "all",
			AuthenticateURLString:    "https://authenticate.example.com",
			AuthenticateCallbackPath: "/oauth2/callback",
			Policies: []config.Policy{{
				From: "https://from.example.com",
				To:   mustParseWeightedURLs(t, "https://to.example.com"),
			}},
		}
		_ = options.Policies[0].Validate()
		routes, err := b.buildPomeriumHTTPRoutes(options, "from.example.com")
		require.NoError(t, err)

		testutil.AssertProtoJSONEqual(t, `[
			`+routeString("path", "/.pomerium/jwt", true)+`,
			`+routeString("path", urlutil.WebAuthnURLPath, true)+`,
			`+routeString("path", "/ping", false)+`,
			`+routeString("path", "/healthz", false)+`,
			`+routeString("path", "/.pomerium", false)+`,
			`+routeString("prefix", "/.pomerium/", false)+`,
			`+routeString("path", "/.well-known/pomerium", false)+`,
			`+routeString("prefix", "/.well-known/pomerium/", false)+`,
			`+routeString("path", "/robots.txt", false)+`
		]`, routes)
	})

	t.Run("without robots", func(t *testing.T) {
		options := &config.Options{
			Services:                 "all",
			AuthenticateURLString:    "https://authenticate.example.com",
			AuthenticateCallbackPath: "/oauth2/callback",
			Policies: []config.Policy{{
				From:                             "https://from.example.com",
				To:                               mustParseWeightedURLs(t, "https://to.example.com"),
				AllowPublicUnauthenticatedAccess: true,
			}},
		}
		_ = options.Policies[0].Validate()
		routes, err := b.buildPomeriumHTTPRoutes(options, "from.example.com")
		require.NoError(t, err)

		testutil.AssertProtoJSONEqual(t, `[
			`+routeString("path", "/.pomerium/jwt", true)+`,
			`+routeString("path", urlutil.WebAuthnURLPath, true)+`,
			`+routeString("path", "/ping", false)+`,
			`+routeString("path", "/healthz", false)+`,
			`+routeString("path", "/.pomerium", false)+`,
			`+routeString("prefix", "/.pomerium/", false)+`,
			`+routeString("path", "/.well-known/pomerium", false)+`,
			`+routeString("prefix", "/.well-known/pomerium/", false)+`
		]`, routes)
	})
}

func Test_buildControlPlanePathRoute(t *testing.T) {
	b := &Builder{filemgr: filemgr.NewManager()}
	route := b.buildControlPlanePathRoute("/hello/world", false)
	testutil.AssertProtoJSONEqual(t, `
		{
			"name": "pomerium-path-/hello/world",
			"match": {
				"path": "/hello/world"
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
	`, route)
}

func Test_buildControlPlanePrefixRoute(t *testing.T) {
	b := &Builder{filemgr: filemgr.NewManager()}
	route := b.buildControlPlanePrefixRoute("/hello/world/", false)
	testutil.AssertProtoJSONEqual(t, `
		{
			"name": "pomerium-prefix-/hello/world/",
			"match": {
				"prefix": "/hello/world/"
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
	`, route)
}

func TestTimeouts(t *testing.T) {
	defer func(f func(*config.Policy) string) {
		getClusterID = f
	}(getClusterID)
	getClusterID = func(*config.Policy) string { return "policy" }

	getDuration := func(txt string) *time.Duration {
		if txt == "" {
			return nil
		}
		d, err := time.ParseDuration(txt)
		require.NoError(t, err, txt)
		return &d
	}

	testCases := []struct {
		upstream, idle  string
		allowWebsockets bool
		expect          string
	}{
		{"", "", false, `"timeout": "3s"`},
		{"", "", true, `"timeout": "0s", "idleTimeout": "0s"`},
		{"5s", "", true, `"timeout": "5s", "idleTimeout": "0s"`},
		{"", "0s", false, `"timeout": "3s","idleTimeout": "0s"`},
		{"", "5s", false, `"timeout": "3s","idleTimeout": "5s"`},
		{"5s", "", false, `"timeout": "5s"`},
		{"5s", "4s", false, `"timeout": "5s","idleTimeout": "4s"`},
		{"0s", "4s", false, `"timeout": "0s","idleTimeout": "4s"`},
	}

	for _, tc := range testCases {
		b := &Builder{filemgr: filemgr.NewManager()}
		routes, err := b.buildPolicyRoutes(&config.Options{
			CookieName:             "pomerium",
			DefaultUpstreamTimeout: time.Second * 3,
			Policies: []config.Policy{
				{
					Source:          &config.StringURL{URL: mustParseURL(t, "https://example.com")},
					Path:            "/test",
					UpstreamTimeout: getDuration(tc.upstream),
					IdleTimeout:     getDuration(tc.idle),
					AllowWebsockets: tc.allowWebsockets,
				},
			},
		}, "example.com")
		if !assert.NoError(t, err, "%v", tc) || !assert.Len(t, routes, 1, tc) || !assert.NotNil(t, routes[0].GetRoute(), "%v", tc) {
			continue
		}

		expect := fmt.Sprintf(`{
			%s,
			"autoHostRewrite": true,
			"cluster": "policy",
			"hashPolicy": [
				{
					"header": {
						"headerName": "x-pomerium-routing-key"
					},
					"terminal": true
				},
				{
					"connectionProperties": {
						"sourceIp": true
					},
					"terminal": true
				}
			],
			"upgradeConfigs": [
				{ "enabled": %v, "upgradeType": "websocket"},
				{ "enabled": false, "upgradeType": "spdy/3.1"}
			]
		}`, tc.expect, tc.allowWebsockets)
		testutil.AssertProtoJSONEqual(t, expect, routes[0].GetRoute())
	}
}

func Test_buildPolicyRoutes(t *testing.T) {
	defer func(f func(*config.Policy) string) {
		getClusterID = f
	}(getClusterID)
	getClusterID = policyNameFunc()

	oneMinute := time.Minute
	ten := time.Second * 10

	b := &Builder{filemgr: filemgr.NewManager()}
	routes, err := b.buildPolicyRoutes(&config.Options{
		CookieName:             "pomerium",
		DefaultUpstreamTimeout: time.Second * 3,
		Policies: []config.Policy{
			{
				Source:              &config.StringURL{URL: mustParseURL(t, "https://ignore.example.com")},
				PassIdentityHeaders: true,
			},
			{
				Source:              &config.StringURL{URL: mustParseURL(t, "https://example.com")},
				PassIdentityHeaders: true,
			},
			{
				Source:              &config.StringURL{URL: mustParseURL(t, "https://example.com")},
				Path:                "/some/path",
				AllowWebsockets:     true,
				PreserveHostHeader:  true,
				PassIdentityHeaders: true,
			},
			{
				Source:              &config.StringURL{URL: mustParseURL(t, "https://example.com")},
				Prefix:              "/some/prefix/",
				SetRequestHeaders:   map[string]string{"HEADER-KEY": "HEADER-VALUE"},
				UpstreamTimeout:     &oneMinute,
				PassIdentityHeaders: true,
			},
			{
				Source:              &config.StringURL{URL: mustParseURL(t, "https://example.com")},
				Regex:               `^/[a]+$`,
				PassIdentityHeaders: true,
			},
			{
				Source:               &config.StringURL{URL: mustParseURL(t, "https://example.com")},
				Prefix:               "/some/prefix/",
				RemoveRequestHeaders: []string{"HEADER-KEY"},
				UpstreamTimeout:      &oneMinute,
				PassIdentityHeaders:  true,
			},
			{
				Source:              &config.StringURL{URL: mustParseURL(t, "https://example.com")},
				Path:                "/some/path",
				AllowSPDY:           true,
				PreserveHostHeader:  true,
				PassIdentityHeaders: true,
			},
			{
				Source:              &config.StringURL{URL: mustParseURL(t, "https://example.com")},
				Path:                "/some/path",
				AllowSPDY:           true,
				AllowWebsockets:     true,
				PreserveHostHeader:  true,
				PassIdentityHeaders: true,
			},
			{
				Source:              &config.StringURL{URL: mustParseURL(t, "https://example.com")},
				Path:                "/websocket-timeout",
				AllowWebsockets:     true,
				PreserveHostHeader:  true,
				PassIdentityHeaders: true,
				UpstreamTimeout:     &ten,
			},
		},
	}, "example.com")
	require.NoError(t, err)

	testutil.AssertProtoJSONEqual(t, `
		[
			{
				"name": "policy-1",
				"match": {
					"prefix": "/"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium",
							"rewrite_response_headers": []
						}
					}
				},
				"route": {
					"autoHostRewrite": true,
					"cluster": "policy-1",
					"hashPolicy": [
						{
							"header": {
								"headerName": "x-pomerium-routing-key"
							},
							"terminal": true
						},
						{
							"connectionProperties": {
								"sourceIp": true
							},
							"terminal": true
						}
					],
					"timeout": "3s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
				},
				"requestHeadersToRemove": [
					"x-pomerium-reproxy-policy",
					"x-pomerium-reproxy-policy-hmac"
				]
			},
			{
				"name": "policy-2",
				"match": {
					"path": "/some/path"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium",
							"rewrite_response_headers": []
						}
					}
				},
				"route": {
					"autoHostRewrite": false,
					"cluster": "policy-2",
					"hashPolicy": [
						{
							"header": {
								"headerName": "x-pomerium-routing-key"
							},
							"terminal": true
						},
						{
							"connectionProperties": {
								"sourceIp": true
							},
							"terminal": true
						}
					],
					"idleTimeout": "0s",
					"timeout": "0s",
					"upgradeConfigs": [
						{ "enabled": true, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
				},
				"requestHeadersToRemove": [
					"x-pomerium-reproxy-policy",
					"x-pomerium-reproxy-policy-hmac"
				]
			},
			{
				"name": "policy-3",
				"match": {
					"prefix": "/some/prefix/"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium",
							"rewrite_response_headers": []
						}
					}
				},
				"route": {
					"autoHostRewrite": true,
					"cluster": "policy-3",
					"hashPolicy": [
						{
							"header": {
								"headerName": "x-pomerium-routing-key"
							},
							"terminal": true
						},
						{
							"connectionProperties": {
								"sourceIp": true
							},
							"terminal": true
						}
					],
					"timeout": "60s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
				},
				"requestHeadersToAdd": [{
					"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
					"header": {
						"key": "HEADER-KEY",
						"value": "HEADER-VALUE"
					}
				}],
				"requestHeadersToRemove": [
					"x-pomerium-reproxy-policy",
					"x-pomerium-reproxy-policy-hmac"
				]
			},
			{
				"name": "policy-4",
				"match": {
					"safeRegex": {
						"googleRe2": {},
						"regex": "^/[a]+$"
					}
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium",
							"rewrite_response_headers": []
						}
					}
				},
				"route": {
					"autoHostRewrite": true,
					"cluster": "policy-4",
					"hashPolicy": [
						{
							"header": {
								"headerName": "x-pomerium-routing-key"
							},
							"terminal": true
						},
						{
							"connectionProperties": {
								"sourceIp": true
							},
							"terminal": true
						}
					],
					"timeout": "3s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
				},
				"requestHeadersToRemove": [
					"x-pomerium-reproxy-policy",
					"x-pomerium-reproxy-policy-hmac"
				]
			},
			{
				"name": "policy-5",
				"match": {
					"prefix": "/some/prefix/"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium",
							"rewrite_response_headers": []
						}
					}
				},
				"route": {
					"autoHostRewrite": true,
					"cluster": "policy-5",
					"hashPolicy": [
						{
							"header": {
								"headerName": "x-pomerium-routing-key"
							},
							"terminal": true
						},
						{
							"connectionProperties": {
								"sourceIp": true
							},
							"terminal": true
						}
					],
					"timeout": "60s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
				},
				"requestHeadersToRemove": [
					"HEADER-KEY",
					"x-pomerium-reproxy-policy",
					"x-pomerium-reproxy-policy-hmac"
				]
			},
			{
				"name": "policy-6",
				"match": {
					"path": "/some/path"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium",
							"rewrite_response_headers": []
						}
					}
				},
				"route": {
					"autoHostRewrite": false,
					"cluster": "policy-6",
					"hashPolicy": [
						{
							"header": {
								"headerName": "x-pomerium-routing-key"
							},
							"terminal": true
						},
						{
							"connectionProperties": {
								"sourceIp": true
							},
							"terminal": true
						}
					],
					"timeout": "3s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": true, "upgradeType": "spdy/3.1"}
					]
				},
				"requestHeadersToRemove": [
					"x-pomerium-reproxy-policy",
					"x-pomerium-reproxy-policy-hmac"
				]
			},
			{
				"name": "policy-7",
				"match": {
					"path": "/some/path"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium",
							"rewrite_response_headers": []
						}
					}
				},
				"route": {
					"autoHostRewrite": false,
					"cluster": "policy-7",
					"hashPolicy": [
						{
							"header": {
								"headerName": "x-pomerium-routing-key"
							},
							"terminal": true
						},
						{
							"connectionProperties": {
								"sourceIp": true
							},
							"terminal": true
						}
					],
					"idleTimeout": "0s",
					"timeout": "0s",
					"upgradeConfigs": [
						{ "enabled": true, "upgradeType": "websocket"},
						{ "enabled": true, "upgradeType": "spdy/3.1"}
					]
				},
				"requestHeadersToRemove": [
					"x-pomerium-reproxy-policy",
					"x-pomerium-reproxy-policy-hmac"
				]
			},
			{
				"name": "policy-8",
				"match": {
					"path": "/websocket-timeout"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium",
							"rewrite_response_headers": []
						}
					}
				},
				"route": {
					"autoHostRewrite": false,
					"cluster": "policy-8",
					"hashPolicy": [
						{
							"header": {
								"headerName": "x-pomerium-routing-key"
							},
							"terminal": true
						},
						{
							"connectionProperties": {
								"sourceIp": true
							},
							"terminal": true
						}
					],
					"idleTimeout": "0s",
					"timeout": "10s",
					"upgradeConfigs": [
						{ "enabled": true, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
				},
				"requestHeadersToRemove": [
					"x-pomerium-reproxy-policy",
					"x-pomerium-reproxy-policy-hmac"
				]
			}
		]
	`, routes)

	t.Run("fronting-authenticate", func(t *testing.T) {
		routes, err := b.buildPolicyRoutes(&config.Options{
			AuthenticateURLString:  "https://authenticate.example.com",
			Services:               "proxy",
			CookieName:             "pomerium",
			DefaultUpstreamTimeout: time.Second * 3,
			Policies: []config.Policy{
				{
					Source:              &config.StringURL{URL: mustParseURL(t, "https://authenticate.example.com")},
					PassIdentityHeaders: true,
				},
			},
		}, "authenticate.example.com")
		require.NoError(t, err)

		testutil.AssertProtoJSONEqual(t, `
			[
				{
					"name": "policy-0",
					"match": {
						"prefix": "/"
					},
					"metadata": {
						"filterMetadata": {
							"envoy.filters.http.lua": {
								"rewrite_response_headers": []
							}
						}
					},
					"route": {
						"autoHostRewrite": true,
						"cluster": "policy-9",
						"hashPolicy": [
							{
								"header": {
									"headerName": "x-pomerium-routing-key"
								},
								"terminal": true
							},
							{
								"connectionProperties": {
									"sourceIp": true
								},
								"terminal": true
							}
						],
						"timeout": "3s",
						"upgradeConfigs": [
							{ "enabled": false, "upgradeType": "websocket"},
							{ "enabled": false, "upgradeType": "spdy/3.1"}
						]
					},
        	        "requestHeadersToRemove": [
        	           	"x-pomerium-reproxy-policy",
        	           	"x-pomerium-reproxy-policy-hmac"
					],
					"typedPerFilterConfig": {
						"envoy.filters.http.ext_authz": {
							"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
							"disabled": true
						}
					}
				}
			]
		`, routes)
	})

	t.Run("tcp", func(t *testing.T) {
		routes, err := b.buildPolicyRoutes(&config.Options{
			CookieName:             "pomerium",
			DefaultUpstreamTimeout: time.Second * 3,
			Policies: []config.Policy{
				{
					Source:              &config.StringURL{URL: mustParseURL(t, "tcp+https://example.com:22")},
					PassIdentityHeaders: true,
				},
				{
					Source:              &config.StringURL{URL: mustParseURL(t, "tcp+https://example.com:22")},
					PassIdentityHeaders: true,
					UpstreamTimeout:     &ten,
				},
			},
		}, "example.com:22")
		require.NoError(t, err)

		testutil.AssertProtoJSONEqual(t, `
		[
			{
				"name": "policy-0",
				"match": {
					"connectMatcher": {}
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium",
							"rewrite_response_headers": []
						}
					}
				},
				"route": {
					"autoHostRewrite": true,
					"cluster": "policy-10",
					"hashPolicy": [
						{
							"header": {
								"headerName": "x-pomerium-routing-key"
							},
							"terminal": true
						},
						{
							"connectionProperties": {
								"sourceIp": true
							},
							"terminal": true
						}
					],
					"idleTimeout": "0s",
					"timeout": "0s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"},
						{ "enabled": true, "upgradeType": "CONNECT", "connectConfig": {} }
					]
				},
				"requestHeadersToRemove": [
					"x-pomerium-reproxy-policy",
					"x-pomerium-reproxy-policy-hmac"
				]
			},
			{
				"name": "policy-1",
				"match": {
					"connectMatcher": {}
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium",
							"rewrite_response_headers": []
						}
					}
				},
				"route": {
					"autoHostRewrite": true,
					"cluster": "policy-11",
					"hashPolicy": [
						{
							"header": {
								"headerName": "x-pomerium-routing-key"
							},
							"terminal": true
						},
						{
							"connectionProperties": {
								"sourceIp": true
							},
							"terminal": true
						}
					],
					"idleTimeout": "0s",
					"timeout": "10s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"},
						{ "enabled": true, "upgradeType": "CONNECT", "connectConfig": {} }
					]
				},
				"requestHeadersToRemove": [
					"x-pomerium-reproxy-policy",
					"x-pomerium-reproxy-policy-hmac"
				]
			}
		]
	`, routes)
	})

	t.Run("remove-pomerium-headers", func(t *testing.T) {
		routes, err := b.buildPolicyRoutes(&config.Options{
			AuthenticateURLString:  "https://authenticate.example.com",
			Services:               "proxy",
			CookieName:             "pomerium",
			DefaultUpstreamTimeout: time.Second * 3,
			JWTClaimsHeaders: map[string]string{
				"x-email": "email",
			},
			Policies: []config.Policy{
				{
					Source: &config.StringURL{URL: mustParseURL(t, "https://from.example.com")},
				},
			},
		}, "from.example.com")
		require.NoError(t, err)

		testutil.AssertProtoJSONEqual(t, `
			[
				{
					"name": "policy-0",
					"match": {
						"prefix": "/"
					},
					"metadata": {
						"filterMetadata": {
							"envoy.filters.http.lua": {
								"remove_impersonate_headers": false,
								"remove_pomerium_authorization": true,
								"remove_pomerium_cookie": "pomerium",
								"rewrite_response_headers": []
							}
						}
					},
					"route": {
						"autoHostRewrite": true,
						"cluster": "policy-12",
						"hashPolicy": [
							{
								"header": {
									"headerName": "x-pomerium-routing-key"
								},
								"terminal": true
							},
							{
								"connectionProperties": {
									"sourceIp": true
								},
								"terminal": true
							}
						],
						"timeout": "3s",
						"upgradeConfigs": [
							{ "enabled": false, "upgradeType": "websocket"},
							{ "enabled": false, "upgradeType": "spdy/3.1"}
						]
					},
					"requestHeadersToRemove": [
						"x-pomerium-jwt-assertion",
						"x-pomerium-jwt-assertion-for",
						"x-email",
						"x-pomerium-reproxy-policy",
						"x-pomerium-reproxy-policy-hmac"
					]
				}
			]
		`, routes)
	})
}

func Test_buildPolicyRoutesRewrite(t *testing.T) {
	defer func(f func(*config.Policy) string) {
		getClusterID = f
	}(getClusterID)
	getClusterID = policyNameFunc()
	b := &Builder{filemgr: filemgr.NewManager()}
	routes, err := b.buildPolicyRoutes(&config.Options{
		CookieName:             "pomerium",
		DefaultUpstreamTimeout: time.Second * 3,
		Policies: []config.Policy{
			{
				Source:              &config.StringURL{URL: mustParseURL(t, "https://example.com")},
				To:                  mustParseWeightedURLs(t, "https://foo.example.com/bar"),
				PassIdentityHeaders: true,
			},
			{
				Source:              &config.StringURL{URL: mustParseURL(t, "https://example.com")},
				To:                  mustParseWeightedURLs(t, "https://foo.example.com/bar"),
				PassIdentityHeaders: true,
				PrefixRewrite:       "/foo",
			},
			{
				Source:                   &config.StringURL{URL: mustParseURL(t, "https://example.com")},
				To:                       mustParseWeightedURLs(t, "https://foo.example.com/bar"),
				PassIdentityHeaders:      true,
				RegexRewritePattern:      "^/service/([^/]+)(/.*)$",
				RegexRewriteSubstitution: "\\2/instance/\\1",
			},
			{
				Source:              &config.StringURL{URL: mustParseURL(t, "https://example.com")},
				To:                  mustParseWeightedURLs(t, "https://foo.example.com/bar"),
				PassIdentityHeaders: true,
				HostRewrite:         "literal.example.com",
			},
			{
				Source:              &config.StringURL{URL: mustParseURL(t, "https://example.com")},
				To:                  mustParseWeightedURLs(t, "https://foo.example.com/bar"),
				PassIdentityHeaders: true,
				HostRewriteHeader:   "HOST_HEADER",
			},
			{
				Source:                           &config.StringURL{URL: mustParseURL(t, "https://example.com")},
				To:                               mustParseWeightedURLs(t, "https://foo.example.com/bar"),
				PassIdentityHeaders:              true,
				HostPathRegexRewritePattern:      "^/(.+)/.+$",
				HostPathRegexRewriteSubstitution: "\\1",
			},
		},
	}, "example.com")
	require.NoError(t, err)

	testutil.AssertProtoJSONEqual(t, `
		[
			{
				"name": "policy-0",
				"match": {
					"prefix": "/"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium",
							"rewrite_response_headers": []
						}
					}
				},
				"route": {
					"autoHostRewrite": true,
					"prefixRewrite": "/bar",
					"cluster": "policy-1",
					"hashPolicy": [
						{
							"header": {
								"headerName": "x-pomerium-routing-key"
							},
							"terminal": true
						},
						{
							"connectionProperties": {
								"sourceIp": true
							},
							"terminal": true
						}
					],
					"timeout": "3s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
				},
				"requestHeadersToRemove": [
					"x-pomerium-reproxy-policy",
					"x-pomerium-reproxy-policy-hmac"
				]
			},
			{
				"name": "policy-1",
				"match": {
					"prefix": "/"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium",
							"rewrite_response_headers": []
						}
					}
				},
				"route": {
					"autoHostRewrite": true,
					"prefixRewrite": "/foo",
					"cluster": "policy-2",
					"hashPolicy": [
						{
							"header": {
								"headerName": "x-pomerium-routing-key"
							},
							"terminal": true
						},
						{
							"connectionProperties": {
								"sourceIp": true
							},
							"terminal": true
						}
					],
					"timeout": "3s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
				},
				"requestHeadersToRemove": [
					"x-pomerium-reproxy-policy",
					"x-pomerium-reproxy-policy-hmac"
				]
			},
			{
				"name": "policy-2",
				"match": {
					"prefix": "/"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium",
							"rewrite_response_headers": []
						}
					}
				},
				"route": {
					"autoHostRewrite": true,
					"regexRewrite": {
						"pattern": {
							"googleRe2": {},
							"regex": "^/service/([^/]+)(/.*)$"
						},
						"substitution": "\\2/instance/\\1"
					},
					"cluster": "policy-3",
					"hashPolicy": [
						{
							"header": {
								"headerName": "x-pomerium-routing-key"
							},
							"terminal": true
						},
						{
							"connectionProperties": {
								"sourceIp": true
							},
							"terminal": true
						}
					],
					"timeout": "3s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
				},
				"requestHeadersToRemove": [
					"x-pomerium-reproxy-policy",
					"x-pomerium-reproxy-policy-hmac"
				]
			},
			{
				"name": "policy-3",
				"match": {
					"prefix": "/"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium",
							"rewrite_response_headers": []
						}
					}
				},
				"route": {
					"hostRewriteLiteral": "literal.example.com",
					"prefixRewrite": "/bar",
					"cluster": "policy-4",
					"hashPolicy": [
						{
							"header": {
								"headerName": "x-pomerium-routing-key"
							},
							"terminal": true
						},
						{
							"connectionProperties": {
								"sourceIp": true
							},
							"terminal": true
						}
					],
					"timeout": "3s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
				},
				"requestHeadersToRemove": [
					"x-pomerium-reproxy-policy",
					"x-pomerium-reproxy-policy-hmac"
				]
			},
			{
				"name": "policy-4",
				"match": {
					"prefix": "/"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium",
							"rewrite_response_headers": []
						}
					}
				},
				"route": {
					"hostRewriteHeader": "HOST_HEADER",
					"prefixRewrite": "/bar",
					"cluster": "policy-5",
					"hashPolicy": [
						{
							"header": {
								"headerName": "x-pomerium-routing-key"
							},
							"terminal": true
						},
						{
							"connectionProperties": {
								"sourceIp": true
							},
							"terminal": true
						}
					],
					"timeout": "3s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
				},
				"requestHeadersToRemove": [
					"x-pomerium-reproxy-policy",
					"x-pomerium-reproxy-policy-hmac"
				]
			},
			{
				"name": "policy-5",
				"match": {
					"prefix": "/"
				},
				"metadata": {
					"filterMetadata": {
						"envoy.filters.http.lua": {
							"remove_impersonate_headers": false,
							"remove_pomerium_authorization": true,
							"remove_pomerium_cookie": "pomerium",
							"rewrite_response_headers": []
						}
					}
				},
				"route": {
					"hostRewritePathRegex": {
						"pattern": {
							"googleRe2": {},
							"regex": "^/(.+)/.+$"
						},
						"substitution": "\\1"
					},
					"prefixRewrite": "/bar",
					"cluster": "policy-6",
					"hashPolicy": [
						{
							"header": {
								"headerName": "x-pomerium-routing-key"
							},
							"terminal": true
						},
						{
							"connectionProperties": {
								"sourceIp": true
							},
							"terminal": true
						}
					],
					"timeout": "3s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"}
					]
				},
				"requestHeadersToRemove": [
					"x-pomerium-reproxy-policy",
					"x-pomerium-reproxy-policy-hmac"
				]
			}
		]
	`, routes)
}

func Test_buildPolicyRouteRedirectAction(t *testing.T) {
	b := &Builder{filemgr: filemgr.NewManager()}
	t.Run("HTTPSRedirect", func(t *testing.T) {
		action, err := b.buildPolicyRouteRedirectAction(&config.PolicyRedirect{
			HTTPSRedirect: proto.Bool(true),
		})
		require.NoError(t, err)
		assert.Equal(t, &envoy_config_route_v3.RedirectAction{
			SchemeRewriteSpecifier: &envoy_config_route_v3.RedirectAction_HttpsRedirect{
				HttpsRedirect: true,
			},
		}, action)

		action, err = b.buildPolicyRouteRedirectAction(&config.PolicyRedirect{
			HTTPSRedirect: proto.Bool(false),
		})
		require.NoError(t, err)
		assert.Equal(t, &envoy_config_route_v3.RedirectAction{
			SchemeRewriteSpecifier: &envoy_config_route_v3.RedirectAction_HttpsRedirect{
				HttpsRedirect: false,
			},
		}, action)
	})
	t.Run("SchemeRedirect", func(t *testing.T) {
		action, err := b.buildPolicyRouteRedirectAction(&config.PolicyRedirect{
			SchemeRedirect: proto.String("https"),
		})
		require.NoError(t, err)
		assert.Equal(t, &envoy_config_route_v3.RedirectAction{
			SchemeRewriteSpecifier: &envoy_config_route_v3.RedirectAction_SchemeRedirect{
				SchemeRedirect: "https",
			},
		}, action)
	})
	t.Run("HostRedirect", func(t *testing.T) {
		action, err := b.buildPolicyRouteRedirectAction(&config.PolicyRedirect{
			HostRedirect: proto.String("HOST"),
		})
		require.NoError(t, err)
		assert.Equal(t, &envoy_config_route_v3.RedirectAction{
			HostRedirect: "HOST",
		}, action)
	})
	t.Run("PortRedirect", func(t *testing.T) {
		action, err := b.buildPolicyRouteRedirectAction(&config.PolicyRedirect{
			PortRedirect: proto.Uint32(1234),
		})
		require.NoError(t, err)
		assert.Equal(t, &envoy_config_route_v3.RedirectAction{
			PortRedirect: 1234,
		}, action)
	})
	t.Run("PathRedirect", func(t *testing.T) {
		action, err := b.buildPolicyRouteRedirectAction(&config.PolicyRedirect{
			PathRedirect: proto.String("PATH"),
		})
		require.NoError(t, err)
		assert.Equal(t, &envoy_config_route_v3.RedirectAction{
			PathRewriteSpecifier: &envoy_config_route_v3.RedirectAction_PathRedirect{
				PathRedirect: "PATH",
			},
		}, action)
	})
	t.Run("PrefixRewrite", func(t *testing.T) {
		action, err := b.buildPolicyRouteRedirectAction(&config.PolicyRedirect{
			PrefixRewrite: proto.String("PREFIX_REWRITE"),
		})
		require.NoError(t, err)
		assert.Equal(t, &envoy_config_route_v3.RedirectAction{
			PathRewriteSpecifier: &envoy_config_route_v3.RedirectAction_PrefixRewrite{
				PrefixRewrite: "PREFIX_REWRITE",
			},
		}, action)
	})
	t.Run("ResponseCode", func(t *testing.T) {
		action, err := b.buildPolicyRouteRedirectAction(&config.PolicyRedirect{
			ResponseCode: proto.Int32(301),
		})
		require.NoError(t, err)
		assert.Equal(t, &envoy_config_route_v3.RedirectAction{
			ResponseCode: 301,
		}, action)
	})
	t.Run("StripQuery", func(t *testing.T) {
		action, err := b.buildPolicyRouteRedirectAction(&config.PolicyRedirect{
			StripQuery: proto.Bool(true),
		})
		require.NoError(t, err)
		assert.Equal(t, &envoy_config_route_v3.RedirectAction{
			StripQuery: true,
		}, action)
	})
}

func TestPolicyName(t *testing.T) {
	// policy names should form a unique ID when converted to envoy cluster names
	// however for metrics purposes we keep original name if present
	assert.NotEmpty(t, getClusterID(&config.Policy{}))
	assert.Empty(t, getClusterStatsName(&config.Policy{}))
	assert.True(t, strings.HasPrefix(getClusterID(&config.Policy{EnvoyOpts: &envoy_config_cluster_v3.Cluster{Name: "my-pomerium-cluster"}}), "my-pomerium-cluster"))
	assert.NotEqual(t, getClusterID(&config.Policy{EnvoyOpts: &envoy_config_cluster_v3.Cluster{Name: "my-pomerium-cluster"}}), "my-pomerium-cluster")
	assert.Equal(t, getClusterStatsName(&config.Policy{EnvoyOpts: &envoy_config_cluster_v3.Cluster{Name: "my-pomerium-cluster"}}), "my-pomerium-cluster")
}

func mustParseURL(t *testing.T, str string) *url.URL {
	u, err := url.Parse(str)
	require.NoError(t, err, str)
	return u
}
