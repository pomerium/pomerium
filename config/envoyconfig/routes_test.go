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
	"github.com/pomerium/pomerium/internal/httputil/reproxy"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func policyNameFunc() func(*config.Policy) string {
	i := 0
	return func(*config.Policy) string {
		i++
		return fmt.Sprintf("policy-%d", i)
	}
}

func Test_buildGRPCRoutes(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

	b := &Builder{filemgr: filemgr.NewManager()}
	routeString := func(typ, name string) string {
		str := `{
			"name": "pomerium-` + typ + `-` + name + `",
			"decorator": {
				"operation": "internal: ${method} ${host}${path}"
			},
			"match": {
				"` + typ + `": "` + name + `"
			},
			"responseHeadersToAdd": [
				{
					"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
					"header": {
						"key": "X-Frame-Options",
						"value": "SAMEORIGIN"
					}
				},
				{
					"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
					"header": {
						"key": "X-XSS-Protection",
						"value": "1; mode=block"
					}
				}
			],
			"route": {
				"cluster": "pomerium-control-plane-http"
			},
			"typedPerFilterConfig": {
				"envoy.filters.http.ext_authz": {
					"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
					"checkSettings": {
						"contextExtensions": {
							"internal": "true",
							"route_checksum": "0",
							"route_id": ""
						}
					}
				}
			}
		}`
		return str
	}
	t.Run("authenticate", func(t *testing.T) {
		options := &config.Options{
			Services:              "all",
			AuthenticateURLString: "https://authenticate.example.com",
		}
		routes, err := b.buildPomeriumHTTPRoutes(options, "authenticate.example.com", false)
		require.NoError(t, err)

		testutil.AssertProtoJSONEqual(t, `[
			`+routeString("path", "/ping")+`,
			`+routeString("path", "/healthz")+`,
			`+routeString("path", "/.pomerium")+`,
			`+routeString("prefix", "/.pomerium/")+`,
			`+routeString("path", "/.well-known/pomerium")+`,
			`+routeString("prefix", "/.well-known/pomerium/")+`,
			`+routeString("path", "/oauth2/callback")+`,
			`+routeString("path", "/")+`,
			`+routeString("path", "/robots.txt")+`
		]`, routes)
	})
	t.Run("proxy fronting authenticate", func(t *testing.T) {
		options := &config.Options{
			Services:              "proxy",
			AuthenticateURLString: "https://authenticate.example.com",
		}
		routes, err := b.buildPomeriumHTTPRoutes(options, "authenticate.example.com", false)
		require.NoError(t, err)
		testutil.AssertProtoJSONEqual(t, "null", routes)
	})
}

func Test_buildControlPlanePathRoute(t *testing.T) {
	t.Parallel()

	options := config.NewDefaultOptions()
	b := &Builder{filemgr: filemgr.NewManager()}
	route := b.buildControlPlanePathRoute(options, "/hello/world")
	testutil.AssertProtoJSONEqual(t, `
		{
			"name": "pomerium-path-/hello/world",
			"decorator": {
				"operation": "internal: ${method} ${host}${path}"
			},
			"match": {
				"path": "/hello/world"
			},
			"responseHeadersToAdd": [
				{
					"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
					"header": {
					  "key": "X-Frame-Options",
					  "value": "SAMEORIGIN"
					}
				},
				{
					"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
					"header": {
					  "key": "X-XSS-Protection",
					  "value": "1; mode=block"
					}
				}
			],
			"route": {
				"cluster": "pomerium-control-plane-http"
			},
			"typedPerFilterConfig": {
				"envoy.filters.http.ext_authz": {
					"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
					"checkSettings": {
						"contextExtensions": {
							"internal": "true",
							"route_checksum": "0",
							"route_id": ""
						}
					}
				}
			}
		}
	`, route)
}

func Test_buildControlPlanePrefixRoute(t *testing.T) {
	t.Parallel()

	options := config.NewDefaultOptions()
	b := &Builder{filemgr: filemgr.NewManager()}
	route := b.buildControlPlanePrefixRoute(options, "/hello/world/")
	testutil.AssertProtoJSONEqual(t, `
		{
			"name": "pomerium-prefix-/hello/world/",
			"decorator": {
				"operation": "internal: ${method} ${host}${path}"
			},
			"match": {
				"prefix": "/hello/world/"
			},
			"responseHeadersToAdd": [
				{
					"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
					"header": {
					  "key": "X-Frame-Options",
					  "value": "SAMEORIGIN"
					}
				},
				{
					"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
					"header": {
					  "key": "X-XSS-Protection",
					  "value": "1; mode=block"
					}
				}
			],
			"route": {
				"cluster": "pomerium-control-plane-http"
			},
			"typedPerFilterConfig": {
				"envoy.filters.http.ext_authz": {
					"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
					"checkSettings": {
						"contextExtensions": {
							"internal": "true",
							"route_checksum": "0",
							"route_id": ""
						}
					}
				}
			}
		}
	`, route)
}

func TestTimeouts(t *testing.T) {
	defer func(f func(*config.Policy) string) {
		GetClusterID = f
	}(GetClusterID)
	GetClusterID = func(*config.Policy) string { return "policy" }

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
		routes, err := b.buildRoutesForPoliciesWithHost(&config.Config{Options: &config.Options{
			CookieName:             "pomerium",
			DefaultUpstreamTimeout: time.Second * 3,
			SharedKey:              cryptutil.NewBase64Key(),
			Policies: []config.Policy{
				{
					From:            "https://example.com",
					To:              mustParseWeightedURLs(t, "https://to.example.com"),
					Path:            "/test",
					UpstreamTimeout: getDuration(tc.upstream),
					IdleTimeout:     getDuration(tc.idle),
					AllowWebsockets: tc.allowWebsockets,
				},
			},
		}}, "example.com")
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
		GetClusterID = f
	}(GetClusterID)
	GetClusterID = policyNameFunc()

	oneMinute := time.Minute
	ten := time.Second * 10

	// note: within each policy below, fields that do not affect the route ID
	// are grouped separately, after the fields that do affect the route ID.
	policies := []config.Policy{
		0: { // skipped by host filter
			From: "https://ignore.example.com",
			To:   mustParseWeightedURLs(t, "https://to.example.com"),

			PassIdentityHeaders: ptr(true),
		},
		1: {
			From: "https://example.com",
			To:   mustParseWeightedURLs(t, "https://to.example.com"),

			PassIdentityHeaders: ptr(true),
		},
		2: {
			From: "https://example.com",
			To:   mustParseWeightedURLs(t, "https://to.example.com"),
			Path: "/some/path",

			AllowWebsockets:     true,
			PreserveHostHeader:  true,
			PassIdentityHeaders: ptr(true),
		},
		3: {
			From:   "https://example.com",
			To:     mustParseWeightedURLs(t, "https://to.example.com"),
			Prefix: "/some/prefix/",

			SetRequestHeaders:   map[string]string{"HEADER-KEY": "HEADER-VALUE"},
			UpstreamTimeout:     &oneMinute,
			PassIdentityHeaders: ptr(true),
		},
		4: {
			From:  "https://example.com",
			To:    mustParseWeightedURLs(t, "https://to.example.com"),
			Regex: `^/[a]+$`,

			PassIdentityHeaders: ptr(true),
		},
		5: { // same route ID as 3
			From:   "https://example.com",
			To:     mustParseWeightedURLs(t, "https://to.example.com"),
			Prefix: "/some/prefix/",

			RemoveRequestHeaders: []string{"HEADER-KEY"},
			UpstreamTimeout:      &oneMinute,
			PassIdentityHeaders:  ptr(true),
		},
		6: { // same route ID as 2
			From: "https://example.com",
			To:   mustParseWeightedURLs(t, "https://to.example.com"),
			Path: "/some/path",

			AllowSPDY:           true,
			PreserveHostHeader:  true,
			PassIdentityHeaders: ptr(true),
		},
		7: { // same route ID as 2
			From: "https://example.com",
			To:   mustParseWeightedURLs(t, "https://to.example.com"),
			Path: "/some/path",

			AllowSPDY:           true,
			AllowWebsockets:     true,
			PreserveHostHeader:  true,
			PassIdentityHeaders: ptr(true),
		},
		8: {
			From: "https://example.com",
			To:   mustParseWeightedURLs(t, "https://to.example.com"),
			Path: "/websocket-timeout",

			AllowWebsockets:     true,
			PreserveHostHeader:  true,
			PassIdentityHeaders: ptr(true),
			UpstreamTimeout:     &ten,
		},
	}
	routeIDs := []string{
		1: "bc16089b025e93dc",
		2: "62efb723582dff6f",
		3: "9934ee6936a6388d",
		4: "0923c9f3dc9e302a",
		5: "9934ee6936a6388d", // same as 3
		6: "62efb723582dff6f", // same as 2
		7: "62efb723582dff6f", // same as 2
		8: "301084c3bd94c1ed",
	}
	routeChecksums := []string{
		1: "1285976700977439100",
		2: "16348664107089573545",
		3: "13915370471596121451",
		4: "4362138640256176359",
		5: "15182794066228364657",
		6: "18199613544753686058",
		7: "14034366733158151490",
		8: "3881579797757777335",
	}

	b := &Builder{filemgr: filemgr.NewManager(), reproxy: reproxy.New()}
	routes, err := b.buildRoutesForPoliciesWithHost(&config.Config{Options: &config.Options{
		CookieName:             "pomerium",
		DefaultUpstreamTimeout: time.Second * 3,
		SharedKey:              cryptutil.NewBase64Key(),
		Policies:               policies,
	}}, "example.com")
	require.NoError(t, err)

	testutil.AssertProtoJSONEqual(t, `
		[
			{
				"name": "policy-1",
				"decorator": {
					"operation": "ingress: ${method} ${host}${path}",
					"propagate": false
				},
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
				],
				"responseHeadersToAdd": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-Frame-Options",
						  "value": "SAMEORIGIN"
						}
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-XSS-Protection",
						  "value": "1; mode=block"
						}
					}
				],
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"checkSettings": {
							"contextExtensions": {
								"internal": "false",
								"route_checksum": "`+routeChecksums[1]+`",
								"route_id": "`+routeIDs[1]+`"
							}
						}
					}
				}
			},
			{
				"name": "policy-2",
				"decorator": {
					"operation": "ingress: ${method} ${host}${path}",
					"propagate": false
				},
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
				],
				"responseHeadersToAdd": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-Frame-Options",
						  "value": "SAMEORIGIN"
						}
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-XSS-Protection",
						  "value": "1; mode=block"
						}
					}
				],
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"checkSettings": {
							"contextExtensions": {
								"internal": "false",
								"route_checksum": "`+routeChecksums[2]+`",
								"route_id": "`+routeIDs[2]+`"
							}
						}
					}
				}
			},
			{
				"name": "policy-3",
				"decorator": {
					"operation": "ingress: ${method} ${host}${path}",
					"propagate": false
				},
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
				"requestHeadersToRemove": [
					"x-pomerium-reproxy-policy",
					"x-pomerium-reproxy-policy-hmac"
				],
				"responseHeadersToAdd": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-Frame-Options",
						  "value": "SAMEORIGIN"
						}
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-XSS-Protection",
						  "value": "1; mode=block"
						}
					}
				],
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"checkSettings": {
							"contextExtensions": {
								"internal": "false",
								"route_checksum": "`+routeChecksums[3]+`",
								"route_id": "`+routeIDs[3]+`"
							}
						}
					}
				}
			},
			{
				"name": "policy-4",
				"decorator": {
					"operation": "ingress: ${method} ${host}${path}",
					"propagate": false
				},
				"match": {
					"safeRegex": {
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
				],
				"responseHeadersToAdd": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-Frame-Options",
						  "value": "SAMEORIGIN"
						}
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-XSS-Protection",
						  "value": "1; mode=block"
						}
					}
				],
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"checkSettings": {
							"contextExtensions": {
								"internal": "false",
								"route_checksum": "`+routeChecksums[4]+`",
								"route_id": "`+routeIDs[4]+`"
							}
						}
					}
				}
			},
			{
				"name": "policy-5",
				"decorator": {
					"operation": "ingress: ${method} ${host}${path}",
					"propagate": false
				},
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
				],
				"responseHeadersToAdd": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-Frame-Options",
						  "value": "SAMEORIGIN"
						}
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-XSS-Protection",
						  "value": "1; mode=block"
						}
					}
				],
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"checkSettings": {
							"contextExtensions": {
								"internal": "false",
								"route_checksum": "`+routeChecksums[5]+`",
								"route_id": "`+routeIDs[5]+`"
							}
						}
					}
				}
			},
			{
				"name": "policy-6",
				"decorator": {
					"operation": "ingress: ${method} ${host}${path}",
					"propagate": false
				},
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
				],
				"responseHeadersToAdd": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-Frame-Options",
						  "value": "SAMEORIGIN"
						}
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-XSS-Protection",
						  "value": "1; mode=block"
						}
					}
				],
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"checkSettings": {
							"contextExtensions": {
								"internal": "false",
								"route_checksum": "`+routeChecksums[6]+`",
								"route_id": "`+routeIDs[6]+`"
							}
						}
					}
				}
			},
			{
				"name": "policy-7",
				"decorator": {
					"operation": "ingress: ${method} ${host}${path}",
					"propagate": false
				},
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
				],
				"responseHeadersToAdd": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-Frame-Options",
						  "value": "SAMEORIGIN"
						}
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-XSS-Protection",
						  "value": "1; mode=block"
						}
					}
				],
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"checkSettings": {
							"contextExtensions": {
								"internal": "false",
								"route_checksum": "`+routeChecksums[7]+`",
								"route_id": "`+routeIDs[7]+`"
							}
						}
					}
				}
			},
			{
				"name": "policy-8",
				"decorator": {
					"operation": "ingress: ${method} ${host}${path}",
					"propagate": false
				},
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
				],
				"responseHeadersToAdd": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-Frame-Options",
						  "value": "SAMEORIGIN"
						}
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-XSS-Protection",
						  "value": "1; mode=block"
						}
					}
				],
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"checkSettings": {
							"contextExtensions": {
								"internal": "false",
								"route_checksum": "`+routeChecksums[8]+`",
								"route_id": "`+routeIDs[8]+`"
							}
						}
					}
				}
			}
		]
	`, routes)

	t.Run("fronting-authenticate", func(t *testing.T) {
		routes, err := b.buildRoutesForPoliciesWithHost(&config.Config{Options: &config.Options{
			AuthenticateURLString:  "https://authenticate.example.com",
			Services:               "proxy",
			CookieName:             "pomerium",
			DefaultUpstreamTimeout: time.Second * 3,
			SharedKey:              cryptutil.NewBase64Key(),
			Policies: []config.Policy{
				{
					From:                "https://authenticate.example.com",
					To:                  mustParseWeightedURLs(t, "https://authenticate.internal"),
					PassIdentityHeaders: ptr(true),
				},
			},
		}}, "authenticate.example.com")
		require.NoError(t, err)

		testutil.AssertProtoJSONEqual(t, `
			[
				{
					"name": "policy-0",
					"decorator": {
						"operation": "ingress: ${method} ${host}${path}",
						"propagate": false
					},
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
					"responseHeadersToAdd": [
						{
							"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
							"header": {
							  "key": "X-Frame-Options",
							  "value": "SAMEORIGIN"
							}
						},
						{
							"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
							"header": {
							  "key": "X-XSS-Protection",
							  "value": "1; mode=block"
							}
						}
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
		routes, err := b.buildRoutesForPoliciesWithHost(&config.Config{Options: &config.Options{
			CookieName:             "pomerium",
			DefaultUpstreamTimeout: time.Second * 3,
			SharedKey:              cryptutil.NewBase64Key(),
			Policies: []config.Policy{
				{
					From:                "tcp+https://example.com:22",
					To:                  mustParseWeightedURLs(t, "tcp://to.example.com"),
					PassIdentityHeaders: ptr(true),
				},
				{
					From:                "tcp+https://example.com:22",
					To:                  mustParseWeightedURLs(t, "https://to.example.com"),
					PassIdentityHeaders: ptr(true),
					UpstreamTimeout:     &ten,
				},
			},
		}}, "example.com:22")
		require.NoError(t, err)

		testutil.AssertProtoJSONEqual(t, `
		[
			{
				"name": "policy-0",
				"decorator": {
					"operation": "ingress: ${method} ${host}${path}",
					"propagate": false
				},
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
				],
				"responseHeadersToAdd": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-Frame-Options",
						  "value": "SAMEORIGIN"
						}
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-XSS-Protection",
						  "value": "1; mode=block"
						}
					}
				],
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"checkSettings": {
							"contextExtensions": {
								"internal": "false",
								"route_checksum": "7991820941787281458",
								"route_id": "98f90d58022ca963"
							}
						}
					}
				}
			},
			{
				"name": "policy-1",
				"decorator": {
					"operation": "ingress: ${method} ${host}${path}",
					"propagate": false
				},
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
						{ "enabled": true, "upgradeType": "CONNECT" }
					]
				},
				"requestHeadersToRemove": [
					"x-pomerium-reproxy-policy",
					"x-pomerium-reproxy-policy-hmac"
				],
				"responseHeadersToAdd": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-Frame-Options",
						  "value": "SAMEORIGIN"
						}
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-XSS-Protection",
						  "value": "1; mode=block"
						}
					}
				],
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"checkSettings": {
							"contextExtensions": {
								"internal": "false",
								"route_checksum": "13838401601763289735",
								"route_id": "81175a3a9df11dd8"
							}
						}
					}
				}
			}
		]
	`, routes)
	})

	t.Run("udp", func(t *testing.T) {
		routes, err := b.buildRoutesForPoliciesWithHost(&config.Config{Options: &config.Options{
			CookieName:             "pomerium",
			DefaultUpstreamTimeout: time.Second * 3,
			SharedKey:              cryptutil.NewBase64Key(),
			Policies: []config.Policy{
				{
					From:                "udp+https://example.com:22",
					To:                  mustParseWeightedURLs(t, "udp://to.example.com"),
					PassIdentityHeaders: ptr(true),
				},
			},
		}}, "example.com:22")
		require.NoError(t, err)

		testutil.AssertProtoJSONEqual(t, `
		[
			{
				"name": "policy-0",
				"decorator": {
					"operation": "ingress: ${method} ${host}${path}",
					"propagate": false
				},
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
					"idleTimeout": "0s",
					"timeout": "0s",
					"upgradeConfigs": [
						{ "enabled": false, "upgradeType": "websocket"},
						{ "enabled": false, "upgradeType": "spdy/3.1"},
						{ "enabled": true, "upgradeType": "CONNECT-UDP", "connectConfig": {} }
					]
				},
				"requestHeadersToRemove": [
					"x-pomerium-reproxy-policy",
					"x-pomerium-reproxy-policy-hmac"
				],
				"responseHeadersToAdd": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-Frame-Options",
						  "value": "SAMEORIGIN"
						}
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-XSS-Protection",
						  "value": "1; mode=block"
						}
					}
				],
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"checkSettings": {
							"contextExtensions": {
								"internal": "false",
								"route_checksum": "14743198626078579455",
								"route_id": "ad0a23467bbdb773"
							}
						}
					}
				}
			}
		]
	`, routes)
	})

	t.Run("remove-pomerium-headers", func(t *testing.T) {
		routes, err := b.buildRoutesForPoliciesWithHost(&config.Config{Options: &config.Options{
			AuthenticateURLString:  "https://authenticate.example.com",
			Services:               "proxy",
			CookieName:             "pomerium",
			DefaultUpstreamTimeout: time.Second * 3,
			SharedKey:              cryptutil.NewBase64Key(),
			JWTClaimsHeaders: map[string]string{
				"x-email": "email",
			},
			Policies: []config.Policy{
				{
					From: "https://from.example.com",
					To:   mustParseWeightedURLs(t, "https://to.example.com"),
				},
			},
		}}, "from.example.com")
		require.NoError(t, err)

		testutil.AssertProtoJSONEqual(t, `
			[
				{
					"name": "policy-0",
					"decorator": {
						"operation": "ingress: ${method} ${host}${path}",
						"propagate": false
					},
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
						"cluster": "policy-13",
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
					],
					"responseHeadersToAdd": [
						{
							"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
							"header": {
							  "key": "X-Frame-Options",
							  "value": "SAMEORIGIN"
							}
						},
						{
							"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
							"header": {
							  "key": "X-XSS-Protection",
							  "value": "1; mode=block"
							}
						}
					],
					"typedPerFilterConfig": {
						"envoy.filters.http.ext_authz": {
							"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
							"checkSettings": {
								"contextExtensions": {
									"internal": "false",
									"route_checksum": "8579751329679030770",
									"route_id": "1013c6be524d7fbd"
								}
							}
						}
					}
				}
			]
		`, routes)
	})

	t.Run("kubernetes", func(t *testing.T) {
		routes, err := b.buildRoutesForPoliciesWithHost(&config.Config{Options: &config.Options{
			AuthenticateURLString: "https://authenticate.example.com",
			Services:              "proxy",
			CookieName:            "pomerium",
			SharedKey:             cryptutil.NewBase64Key(),
			Policies: []config.Policy{
				{
					From:                          "https://k8s-in.example.com",
					To:                            mustParseWeightedURLs(t, "https://k8s-out.example.com"),
					KubernetesServiceAccountToken: "KUBERNETES_SERVICE_ACCOUNT_TOKEN",
				},
			},
		}}, "k8s-in.example.com")
		require.NoError(t, err)

		testutil.AssertProtoJSONEqual(t, `
			[
				{
					"name": "policy-0",
					"decorator": {
						"operation": "ingress: ${method} ${host}${path}",
						"propagate": false
					},
					"match": {
						"prefix": "/"
					},
					"metadata": {
						"filterMetadata": {
							"envoy.filters.http.lua": {
								"remove_impersonate_headers": true,
								"remove_pomerium_authorization": true,
								"remove_pomerium_cookie": "pomerium",
								"rewrite_response_headers": []
							}
						}
					},
					"route": {
						"autoHostRewrite": true,
						"cluster": "pomerium-control-plane-http",
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
					"requestHeadersToAdd": [
						{
							"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
							"header": {
								"key": "x-pomerium-reproxy-policy",
								"value": "a81e6b1e66c1e2cd"
							}
						},
						{
							"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
							"header": {
								"key": "x-pomerium-reproxy-policy-hmac",
								"value": "0EisedpElEUeBI5OPTVcMtza+Yyju2lsbSoBya2jBJ0="
							}
						}
					],
					"requestHeadersToRemove": [
						"x-pomerium-jwt-assertion",
						"x-pomerium-jwt-assertion-for",
						"x-pomerium-reproxy-policy",
						"x-pomerium-reproxy-policy-hmac"
					],
					"responseHeadersToAdd": [
						{
							"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
							"header": {
							  "key": "X-Frame-Options",
							  "value": "SAMEORIGIN"
							}
						},
						{
							"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
							"header": {
							  "key": "X-XSS-Protection",
							  "value": "1; mode=block"
							}
						}
					],
					"typedPerFilterConfig": {
						"envoy.filters.http.ext_authz": {
							"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
							"checkSettings": {
								"contextExtensions": {
									"internal": "false",
									"route_checksum": "13049655080604513764",
									"route_id": "a81e6b1e66c1e2cd"
								}
							}
						}
					}
				}
			]
		`, routes)
	})
}

func Test_buildPolicyRoutesRewrite(t *testing.T) {
	defer func(f func(*config.Policy) string) {
		GetClusterID = f
	}(GetClusterID)
	GetClusterID = policyNameFunc()
	b := &Builder{filemgr: filemgr.NewManager()}
	routes, err := b.buildRoutesForPoliciesWithHost(&config.Config{Options: &config.Options{
		CookieName:             "pomerium",
		DefaultUpstreamTimeout: time.Second * 3,
		SharedKey:              cryptutil.NewBase64Key(),
		Policies: []config.Policy{
			{
				From:                "https://example.com",
				To:                  mustParseWeightedURLs(t, "https://foo.example.com/bar"),
				PassIdentityHeaders: ptr(true),
			},
			{
				From:                "https://example.com",
				To:                  mustParseWeightedURLs(t, "https://foo.example.com/bar"),
				PassIdentityHeaders: ptr(true),
				PrefixRewrite:       "/foo",
			},
			{
				From:                     "https://example.com",
				To:                       mustParseWeightedURLs(t, "https://foo.example.com/bar"),
				PassIdentityHeaders:      ptr(true),
				RegexRewritePattern:      "^/service/([^/]+)(/.*)$",
				RegexRewriteSubstitution: "\\2/instance/\\1",
			},
			{
				From:                "https://example.com",
				To:                  mustParseWeightedURLs(t, "https://foo.example.com/bar"),
				PassIdentityHeaders: ptr(true),
				HostRewrite:         "literal.example.com",
			},
			{
				From:                "https://example.com",
				To:                  mustParseWeightedURLs(t, "https://foo.example.com/bar"),
				PassIdentityHeaders: ptr(true),
				HostRewriteHeader:   "HOST_HEADER",
			},
			{
				From:                             "https://example.com",
				To:                               mustParseWeightedURLs(t, "https://foo.example.com/bar"),
				PassIdentityHeaders:              ptr(true),
				HostPathRegexRewritePattern:      "^/(.+)/.+$",
				HostPathRegexRewriteSubstitution: "\\1",
			},
		},
	}}, "example.com")
	require.NoError(t, err)

	testutil.AssertProtoJSONEqual(t, `
		[
			{
				"name": "policy-0",
				"decorator": {
					"operation": "ingress: ${method} ${host}${path}",
					"propagate": false
				},
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
				],
				"responseHeadersToAdd": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-Frame-Options",
						  "value": "SAMEORIGIN"
						}
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-XSS-Protection",
						  "value": "1; mode=block"
						}
					}
				],
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"checkSettings": {
							"contextExtensions": {
								"internal": "false",
								"route_checksum": "236577289533125748",
								"route_id": "4d5ee69fcc359f45"
							}
						}
					}
				}
			},
			{
				"name": "policy-1",
				"decorator": {
					"operation": "ingress: ${method} ${host}${path}",
					"propagate": false
				},
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
				],
				"responseHeadersToAdd": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-Frame-Options",
						  "value": "SAMEORIGIN"
						}
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-XSS-Protection",
						  "value": "1; mode=block"
						}
					}
				],
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"checkSettings": {
							"contextExtensions": {
								"internal": "false",
								"route_checksum": "6547988620230255695",
								"route_id": "4d5ee69fcc359f45"
							}
						}
					}
				}
			},
			{
				"name": "policy-2",
				"decorator": {
					"operation": "ingress: ${method} ${host}${path}",
					"propagate": false
				},
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
				],
				"responseHeadersToAdd": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-Frame-Options",
						  "value": "SAMEORIGIN"
						}
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-XSS-Protection",
						  "value": "1; mode=block"
						}
					}
				],
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"checkSettings": {
							"contextExtensions": {
								"internal": "false",
								"route_checksum": "4450493890676287666",
								"route_id": "4d5ee69fcc359f45"
							}
						}
					}
				}
			},
			{
				"name": "policy-3",
				"decorator": {
					"operation": "ingress: ${method} ${host}${path}",
					"propagate": false
				},
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
				],
				"responseHeadersToAdd": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-Frame-Options",
						  "value": "SAMEORIGIN"
						}
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-XSS-Protection",
						  "value": "1; mode=block"
						}
					}
				],
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"checkSettings": {
							"contextExtensions": {
								"internal": "false",
								"route_checksum": "2851589862481830636",
								"route_id": "4d5ee69fcc359f45"
							}
						}
					}
				}
			},
			{
				"name": "policy-4",
				"decorator": {
					"operation": "ingress: ${method} ${host}${path}",
					"propagate": false
				},
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
				],
				"responseHeadersToAdd": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-Frame-Options",
						  "value": "SAMEORIGIN"
						}
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-XSS-Protection",
						  "value": "1; mode=block"
						}
					}
				],
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"checkSettings": {
							"contextExtensions": {
								"internal": "false",
								"route_checksum": "4024784717608926738",
								"route_id": "4d5ee69fcc359f45"
							}
						}
					}
				}
			},
			{
				"name": "policy-5",
				"decorator": {
					"operation": "ingress: ${method} ${host}${path}",
					"propagate": false
				},
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
				],
				"responseHeadersToAdd": [
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-Frame-Options",
						  "value": "SAMEORIGIN"
						}
					},
					{
						"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
						"header": {
						  "key": "X-XSS-Protection",
						  "value": "1; mode=block"
						}
					}
				],
				"typedPerFilterConfig": {
					"envoy.filters.http.ext_authz": {
						"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
						"checkSettings": {
							"contextExtensions": {
								"internal": "false",
								"route_checksum": "8922706931522049759",
								"route_id": "4d5ee69fcc359f45"
							}
						}
					}
				}
			}
		]
	`, routes)
}

func Test_buildPolicyRouteRedirectAction(t *testing.T) {
	t.Parallel()

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
		codes := []struct {
			Number *int32
			Enum   envoy_config_route_v3.RedirectAction_RedirectResponseCode
		}{
			{nil, envoy_config_route_v3.RedirectAction_MOVED_PERMANENTLY},
			{proto.Int32(301), envoy_config_route_v3.RedirectAction_MOVED_PERMANENTLY},
			{proto.Int32(302), envoy_config_route_v3.RedirectAction_FOUND},
			{proto.Int32(303), envoy_config_route_v3.RedirectAction_SEE_OTHER},
			{proto.Int32(307), envoy_config_route_v3.RedirectAction_TEMPORARY_REDIRECT},
			{proto.Int32(308), envoy_config_route_v3.RedirectAction_PERMANENT_REDIRECT},
		}
		for i := range codes {
			c := &codes[i]
			t.Run(fmt.Sprint(c.Number), func(t *testing.T) {
				action, err := b.buildPolicyRouteRedirectAction(&config.PolicyRedirect{
					ResponseCode: c.Number,
				})
				require.NoError(t, err)
				assert.Equal(t, &envoy_config_route_v3.RedirectAction{
					ResponseCode: c.Enum,
				}, action)
			})
		}
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
	t.Parallel()

	// policy names should form a unique ID when converted to envoy cluster names
	// however for metrics purposes we keep original name if present
	assert.NotEmpty(t, GetClusterID(&config.Policy{}))
	assert.Empty(t, getClusterStatsName(&config.Policy{}))
	assert.True(t, strings.HasPrefix(GetClusterID(&config.Policy{EnvoyOpts: &envoy_config_cluster_v3.Cluster{Name: "my-pomerium-cluster"}}), "my-pomerium-cluster"))
	assert.NotEqual(t, GetClusterID(&config.Policy{EnvoyOpts: &envoy_config_cluster_v3.Cluster{Name: "my-pomerium-cluster"}}), "my-pomerium-cluster")
	assert.Equal(t, getClusterStatsName(&config.Policy{EnvoyOpts: &envoy_config_cluster_v3.Cluster{Name: "my-pomerium-cluster"}}), "my-pomerium-cluster")
}

func mustParseURL(t *testing.T, str string) *url.URL {
	u, err := url.Parse(str)
	require.NoError(t, err, str)
	return u
}

func ptr[T any](v T) *T {
	return &v
}

func Test_buildPomeriumHTTPRoutesWithMCP(t *testing.T) {
	t.Parallel()

	routeString := func(typ, name string) string {
		str := `{
			"name": "pomerium-` + typ + `-` + name + `",
			"decorator": {
				"operation": "internal: ${method} ${host}${path}"
			},
			"match": {
				"` + typ + `": "` + name + `"
			},
			"responseHeadersToAdd": [
				{
					"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
					"header": {
						"key": "X-Frame-Options",
						"value": "SAMEORIGIN"
					}
				},
				{
					"appendAction": "OVERWRITE_IF_EXISTS_OR_ADD",
					"header": {
						"key": "X-XSS-Protection",
						"value": "1; mode=block"
					}
				}
			],
			"route": {
				"cluster": "pomerium-control-plane-http"
			},
			"typedPerFilterConfig": {
				"envoy.filters.http.ext_authz": {
					"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute",
					"checkSettings": {
						"contextExtensions": {
							"internal": "true",
							"route_checksum": "0",
							"route_id": ""
						}
					}
				}
			}
		}`
		return str
	}

	t.Run("without MCP policy", func(t *testing.T) {
		b := &Builder{filemgr: filemgr.NewManager()}
		options := &config.Options{
			Services:              "all",
			AuthenticateURLString: "https://authenticate.example.com",
			Policies: []config.Policy{
				{
					From: "https://example.com",
					To:   mustParseWeightedURLs(t, "https://to.example.com"),
				},
			},
		}

		routes, err := b.buildPomeriumHTTPRoutes(options, "example.com", false)
		require.NoError(t, err)

		hasOAuthServer := false
		for _, route := range routes {
			if route.GetMatch().GetPath() == "/.well-known/oauth-authorization-server" {
				hasOAuthServer = true
			}
		}

		assert.False(t, hasOAuthServer, "/.well-known/oauth-authorization-server route should NOT be present")
	})

	t.Run("with MCP policy", func(t *testing.T) {
		b := &Builder{filemgr: filemgr.NewManager()}
		options := &config.Options{
			Services:              "all",
			AuthenticateURLString: "https://authenticate.example.com",
			Policies: []config.Policy{
				{
					From: "https://example.com",
					To:   mustParseWeightedURLs(t, "https://to.example.com"),
				},
				{
					From: "https://mcp.example.com",
					To:   mustParseWeightedURLs(t, "https://mcp-backend.example.com"),
					MCP:  &config.MCP{Server: &config.MCPServer{}}, // This marks the policy as an MCP policy
				},
			},
			RuntimeFlags: config.DefaultRuntimeFlags(),
		}
		options.RuntimeFlags[config.RuntimeFlagMCP] = true

		routes, err := b.buildPomeriumHTTPRoutes(options, "example.com", true)
		require.NoError(t, err)

		// Verify the expected route structures
		testutil.AssertProtoJSONEqual(t, `[
			`+routeString("path", "/ping")+`,
			`+routeString("path", "/healthz")+`,
			`+routeString("path", "/.pomerium")+`,
			`+routeString("prefix", "/.pomerium/")+`,
			`+routeString("path", "/.well-known/pomerium")+`,
			`+routeString("prefix", "/.well-known/pomerium/")+`,
			`+routeString("path", "/.well-known/oauth-authorization-server")+`,
			`+routeString("prefix", "/.well-known/oauth-protected-resource")+`
		]`, routes)
	})

	t.Run("with MCP policy, runtime flag is off", func(t *testing.T) {
		b := &Builder{filemgr: filemgr.NewManager()}
		options := &config.Options{
			Services:              "all",
			AuthenticateURLString: "https://authenticate.example.com",
			Policies: []config.Policy{
				{
					From: "https://example.com",
					To:   mustParseWeightedURLs(t, "https://to.example.com"),
				},
				{
					From: "https://mcp.example.com",
					To:   mustParseWeightedURLs(t, "https://mcp-backend.example.com"),
					MCP:  &config.MCP{Server: &config.MCPServer{}}, // This marks the policy as an MCP policy
				},
			},
			RuntimeFlags: config.DefaultRuntimeFlags(),
		}
		options.RuntimeFlags[config.RuntimeFlagMCP] = false

		routes, err := b.buildPomeriumHTTPRoutes(options, "example.com", true)
		require.NoError(t, err)

		// Verify the expected route structures
		testutil.AssertProtoJSONEqual(t, `[
			`+routeString("path", "/ping")+`,
			`+routeString("path", "/healthz")+`,
			`+routeString("path", "/.pomerium")+`,
			`+routeString("prefix", "/.pomerium/")+`,
			`+routeString("path", "/.well-known/pomerium")+`,
			`+routeString("prefix", "/.well-known/pomerium/")+`
		]`, routes)
	})
}
